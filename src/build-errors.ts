/**
 * Parse a failed `next build` / `tsc` log into PRECISE, file-localized findings
 * (backlog: auto-fixer localization). The verify gate used to file every build
 * failure as a single `@ package.json` finding with the real cause buried in a
 * 600-char log tail — so the fixer LLM was pointed at the wrong file and couldn't
 * tell WHAT to change. Observed live: it oscillated on an export/import mismatch it
 * was never told the location of.
 *
 * This extracts the structured cause from the common compiler phrasings and names
 * the actual file to edit. The fixer then (a) reads the right file in full and (b)
 * gets a message it can act on. Pure except for `resolveLocalModule`, which reads
 * tsconfig to turn an `@/…` import into a real path; everything degrades to the
 * module string when a file can't be resolved, so it never throws.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "./types.ts";

/** tsconfig `compilerOptions.paths` base(s) for a `@/*`-style alias prefix. */
function aliasBases(projectPath: string): Array<{ prefix: string; bases: string[] }> {
  try {
    const raw = readFileSync(join(projectPath, "tsconfig.json"), "utf8");
    // tolerant parse — tsconfig allows comments/trailing commas; strip the obvious ones
    const json = JSON.parse(raw.replace(/\/\/[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/,(\s*[}\]])/g, "$1"));
    const paths = json?.compilerOptions?.paths ?? {};
    const out: Array<{ prefix: string; bases: string[] }> = [];
    for (const [k, v] of Object.entries(paths)) {
      if (!k.endsWith("/*") || !Array.isArray(v)) continue;
      out.push({ prefix: k.slice(0, -1), bases: (v as string[]).map((b) => b.replace(/\*$/, "")) }); // "@/" → ["./"]
    }
    return out;
  } catch {
    return [{ prefix: "@/", bases: ["./", "./src/"] }]; // sensible default when tsconfig is unreadable
  }
}

const EXTS = ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js"];

/** Resolve a local module specifier (`@/lib/x`, `./x`) to a real file relative to the
 *  project root. Returns null for bare package specifiers (those are npm deps) or when
 *  nothing on disk matches. */
export function resolveLocalModule(module: string, projectPath: string): string | null {
  let rel: string | null = null;
  if (module.startsWith(".") || module.startsWith("/")) {
    rel = module.replace(/^\/+/, "").replace(/^\.\//, "");
  } else {
    for (const { prefix, bases } of aliasBases(projectPath)) {
      if (module.startsWith(prefix)) {
        const rest = module.slice(prefix.length);
        for (const base of bases) {
          const cand = base.replace(/^\.\//, "") + rest;
          for (const ext of EXTS) {
            const p = (cand + ext).replace(/\/+/g, "/");
            if (existsSync(join(projectPath, p))) return p;
          }
        }
      }
    }
    return null; // bare package → not a local file
  }
  for (const ext of EXTS) {
    const p = (rel + ext).replace(/\/+/g, "/");
    if (existsSync(join(projectPath, p))) return p;
  }
  return null;
}

// Anchor each pattern on the word right before the quoted token so an apostrophe
// elsewhere in the sentence can't derail quote matching (see missingdeps.ts).
// `['"]+` consumes nested quote wrappers — TS prints the module double-quoted INSIDE
// its single-quoted error, e.g. Module '"@/lib/x"' has no exported member 'y'.
const IMPORT_NOT_EXPORTED = /import error:\s*['"]+([^'"]+)['"]+ is not exported from\s*['"]+([^'"]+)['"]+/gi;
const NO_EXPORTED_MEMBER = /Module\s+['"]+([^'"]+)['"]+ has no exported member\s*['"]+([^'"]+)['"]+/gi;
const CANNOT_RESOLVE = /(?:resolve|module)\s+['"]([^'"]+)['"]/gi;
// Next.js / tsc print a file:line:col line, then "Type error: <message>". Captures ANY
// type error (e.g. Next 15 async headers()/cookies() not awaited) at its real location.
const TS_TYPE_ERROR = /(?:^|\n)\s*\.?\/?([\w./-]+\.[jt]sx?):(\d+):(\d+)\s*[\r\n]+\s*Type error:\s*([^\r\n]+)/g;
// Raw `tsc --noEmit` format: `path/file.ts(line,col): error TS####: message`. Lets the
// fixer enumerate EVERY type error at once (batched) instead of one-per-`next build`.
const TSC_ERROR = /(?:^|\n)([\w./\\-]+\.[jt]sx?)\((\d+),\d+\):\s*error\s+TS\d+:\s*([^\r\n]+)/g;
// these are handled by the specific export/resolve patterns above — don't also emit a
// generic type-error finding for the same line.
const COVERED_BY_SPECIFIC = /has no exported member|is not exported|Can't resolve|Cannot find module/i;

// An INTERNAL module (@/…, ./…) that the build can't resolve = a file imported but never
// generated. webpack prints the importing file on the line just above the error.
const INTERNAL_NOT_FOUND = /(?:^|\n)\s*\.?\/?([\w./-]+\.[jt]sx?)\s*[\r\n]+\s*Module not found: Can't resolve\s+['"]((?:@\/|\.\.?\/)[^'"]+)['"]/g;

/** Where an unresolved internal module SHOULD live, for an actionable "create this file"
 *  message: `@/lib/supabase/server` → `lib/supabase/server.ts`. */
function intendedPath(module: string): string {
  return module.replace(/^@\//, "").replace(/^\.\.?\//, "") + ".ts";
}

const ANSI = /\[[0-9;]*m/g;

/** Parse a build log into localized findings. Empty when nothing structured matched
 *  (the caller then falls back to a generic finding). `ruleId` is set by the caller. */
export function parseBuildErrors(rawLog: string, projectPath: string, ruleId = "build-failed"): Finding[] {
  const log = rawLog.replace(ANSI, ""); // next/tsc colorize even under a pipe — strip first
  const out: Finding[] = [];
  const seen = new Set<string>();
  const add = (file: string, message: string, line?: number): void => {
    const key = `${file}::${message}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ tool: "verify", ruleId, severity: "high", file, ...(line ? { line } : {}), message });
  };

  // 1) export/member mismatch: 'SYM' is not exported from 'MODULE' (the live failure mode)
  for (const re of [IMPORT_NOT_EXPORTED, NO_EXPORTED_MEMBER]) {
    for (const m of log.matchAll(re)) {
      const a = m[1] ?? "";
      const b = m[2] ?? "";
      // IMPORT_NOT_EXPORTED is (symbol, module); NO_EXPORTED_MEMBER is (module, symbol)
      const [symbol, module] = re === IMPORT_NOT_EXPORTED ? [a, b] : [b, a];
      if (!symbol || !module) continue;
      const resolved = resolveLocalModule(module, projectPath);
      const file = resolved ?? "package.json";
      add(
        file,
        `\`npm run build\` failed — '${symbol}' is not exported from '${module}'${resolved ? ` (${resolved})` : ""}. ` +
          `Reconcile it: either export '${symbol}' from that module, or change every file importing '${symbol}' to use an export that exists. All importers and the module must agree.`,
      );
    }
  }

  // 2) unresolved NPM PACKAGE — keep "Can't resolve 'X'" verbatim so the deterministic
  //    missing-deps installer (missingdeps.ts) still recognizes it.
  for (const m of log.matchAll(CANNOT_RESOLVE)) {
    const module = m[1] ?? "";
    if (!module || module.startsWith(".") || module.startsWith("@/") || module.startsWith("/")) continue;
    add("package.json", `\`npm run build\` failed — Module not found: Can't resolve '${module}'. If it's a real package, it must be added as a dependency; if not, fix the import.`);
  }

  // 2b) unresolved INTERNAL module = a file imported but never generated. Point the fixer
  //     at it explicitly (was previously skipped → collapsed to a generic "build failed",
  //     so the fixer never knew which file to create). De-dupe by module; name an importer.
  const missingInternal = new Map<string, string>(); // module → an importing file
  for (const m of log.matchAll(INTERNAL_NOT_FOUND)) {
    const importer = (m[1] ?? "").replace(/^\.\//, "");
    const module = m[2] ?? "";
    if (module && !resolveLocalModule(module, projectPath) && !missingInternal.has(module)) missingInternal.set(module, importer);
  }
  for (const [module, importer] of missingInternal) {
    const exists = existsSync(join(projectPath, importer));
    add(
      exists ? importer : "package.json",
      `\`npm run build\` failed — Module not found: '${module}' is imported (e.g. in ${importer}) but no such file exists. ` +
        `CREATE the file at ${intendedPath(module)} exporting what its importers use (follow the project's conventions for that module), or fix the import path. Several files import it — they must all resolve.`,
    );
  }

  // 3) any other type error → its real file:line (e.g. Next 15 async headers()/cookies()
  //    not awaited). Skip ones already covered by the specific patterns above.
  for (const m of log.matchAll(TS_TYPE_ERROR)) {
    const rel = (m[1] ?? "").replace(/^\.\//, "");
    const line = Number(m[2]);
    const msg = (m[4] ?? "").trim();
    if (!rel || !msg || COVERED_BY_SPECIFIC.test(msg)) continue;
    const file = existsSync(join(projectPath, rel)) ? rel : "package.json";
    add(file, `\`npm run build\` failed at ${rel}:${line} — Type error: ${msg}`, Number.isFinite(line) ? line : undefined);
  }

  // 4) raw `tsc --noEmit` errors (the BATCHED view) → one finding per real type error, in
  //    a source file. Skip generated (.next/) and node_modules so the fixer is aimed at
  //    files it can actually edit.
  for (const m of log.matchAll(TSC_ERROR)) {
    const rel = (m[1] ?? "").replace(/\\/g, "/").replace(/^\.\//, "");
    const line = Number(m[2]);
    const msg = (m[3] ?? "").trim();
    if (!rel || !msg || rel.startsWith(".next/") || rel.includes("node_modules/") || COVERED_BY_SPECIFIC.test(msg)) continue;
    if (!existsSync(join(projectPath, rel))) continue;
    add(rel, `type error at ${rel}:${line} — ${msg}`, Number.isFinite(line) ? line : undefined);
  }

  return out;
}
