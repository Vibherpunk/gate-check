/**
 * `engines` gate — Node.js version drift. The generated apps this repo ships must
 * declare ONE Node.js version, consistently, across every location that can pin a
 * runtime. The gate catches drift deterministically (zero LLM): it reads every
 * Node-version declaration in the project, normalizes each (`v` prefix stripped,
 * patch zero-padded to 2 digits), and requires they all agree.
 *
 * Locations checked (all four):
 *   • package.json `engines.node`
 *   • Dockerfile `FROM node:<version>…`
 *   • fly.toml any `node_version` / `NODE_VERSION` setting (any section)
 *   • web/ and src/ runtime files that pin a Node version (searched first, then
 *     declared as a location)
 *
 * Behavior:
 *   • exit 0 (pass) if all declarations agree.
 *   • exit 1 (block) if any file declares a version that differs from the rest —
 *     the message lists EVERY offending file with its declared value and the
 *     expected value.
 *   • exit 1 (block) if a canonical root manifest (package.json / Dockerfile /
 *     fly.toml) is MISSING a declaration while another root manifest declares one
 *     — the message names the missing file(s). A web/ or src/ runtime pin counts
 *     as the project's runtime declaration: when one exists, the missing-root
 *     check is satisfied and only AGREEMENT is enforced.
 *   • If NOTHING declares a Node version, exit 0 (nothing to check).
 *
 * The gate is engine-blind: it takes a directory of code, regardless of what
 * produced it. The verdict is deterministic with zero LLM in the path.
 */
import { existsSync, readFileSync } from "node:fs";
import { readdirSync } from "node:fs";
import type { Dirent } from "node:fs";
import { join, resolve } from "node:path";
import type { Finding, Gate, GateVerdict } from "./types.ts";
import { verdictOf } from "./types.ts";

/** A single declared Node version, tied to the file that declared it. */
interface NodeDecl {
  /** Project-relative path (e.g. "Dockerfile", "web/server.ts"). */
  file: string;
  /** The raw declared version string (e.g. "20", "v20.11", "20.11.0"). */
  raw: string;
  /** The normalized form used for comparison ("20.11"). */
  norm: string;
}

/** package.json `engines.node` — a range/semver string; take the leading version. */
function readPackageJsonEngines(projectPath: string): NodeDecl | null {
  const p = join(projectPath, "package.json");
  if (!existsSync(p)) return null;
  let pkg: unknown;
  try {
    pkg = JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null; // malformed → treat as absent; the gate is about declared versions
  }
  const node = (pkg as { engines?: { node?: string } }).engines?.node;
  if (typeof node !== "string" || node.trim() === "") return null;
  const raw = node.trim();
  const norm = normalizeNode(raw);
  return norm ? { file: "package.json", raw, norm } : null;
}

/** Dockerfile `FROM node:<version>` — capture the version tag. */
function readDockerfileNode(projectPath: string): NodeDecl | null {
  for (const name of ["Dockerfile", "dockerfile", "Dockerfile.dev"]) {
    const p = join(projectPath, name);
    if (!existsSync(p)) continue;
    const content = readFileSync(p, "utf8");
    // strip a digest/ref suffix if present after a colon (node:20.11@sha256:…)
    const raw = content.match(/\bFROM\s+node:([^\s]+)/i)?.[1]?.split("@")[0]?.trim();
    if (raw) {
      const norm = normalizeNode(raw);
      if (norm) return { file: name, raw, norm };
    }
  }
  return null;
}

/** fly.toml `node_version` / `NODE_VERSION` — any section. */
function readFlyTomlNode(projectPath: string): NodeDecl | null {
  const p = join(projectPath, "fly.toml");
  if (!existsSync(p)) return null;
  const content = readFileSync(p, "utf8");
  const raw = content.match(/(node_version|NODE_VERSION)\s*=\s*"([^"]+)"/)?.[2]?.trim();
  if (raw) {
    const norm = normalizeNode(raw);
    if (norm) return { file: "fly.toml", raw, norm };
  }
  return null;
}

/**
 * web/ and src/ runtime files that pin a Node version. Search for the common
 * shapes: `FROM node:<v>` (a Dockerfile living in web/src), `engines.node` in a
 * package.json, `node_version`/`NODE_VERSION` in a toml/yaml, or an explicit
 * `node` runtime pin in a config. Returns the first match per file.
 */
function readWebSrcNode(projectPath: string): Map<string, NodeDecl> {
  const out = new Map<string, NodeDecl>();
  const walk = (dir: string, prefix: string): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if ([".git", "node_modules", ".next", "dist", "build"].includes(e.name)) continue;
        walk(full, `${prefix}${e.name}/`);
        continue;
      }
      if (!e.isFile()) continue;
      // Project-relative path (e.g. "web/Dockerfile") — the gate's findings and the
      // web/src grouping both key on this shape (an absolute path would never match).
      const rel = `${prefix}${e.name}`;
      const name = e.name.toLowerCase();
      // Only inspect files that could carry a runtime pin.
      if (!/(dockerfile|\.toml|\.ya?ml|package\.json)$/.test(name)) continue;
      let content: string;
      try {
        content = readFileSync(full, "utf8");
      } catch {
        continue;
      }
      const decl = pickWebSrcDecl(rel, content);
      if (decl) out.set(rel, decl);
    }
  };
  for (const sub of ["web", "src"]) {
    const base = join(projectPath, sub);
    if (existsSync(base)) walk(base, `${sub}/`);
  }
  return out;
}

/** Pick a Node decl from one web/src file, or null. */
function pickWebSrcDecl(rel: string, content: string): NodeDecl | null {
  // Dockerfile-style FROM node:<v>
  const fromRaw = content.match(/\bFROM\s+node:([^\s]+)/i)?.[1]?.split("@")[0]?.trim();
  if (fromRaw) {
    const norm = normalizeNode(fromRaw);
    if (norm) return { file: rel, raw: fromRaw, norm };
  }
  // package.json engines.node
  if (rel.toLowerCase().endsWith("package.json")) {
    try {
      const pkg = JSON.parse(content) as { engines?: { node?: string } };
      const node = pkg.engines?.node;
      if (typeof node === "string" && node.trim()) {
        const norm = normalizeNode(node.trim());
        if (norm) return { file: rel, raw: node.trim(), norm };
      }
    } catch {
      /* ignore malformed */
    }
  }
  // node_version / NODE_VERSION = "x" in a toml/yaml
  const raw = content.match(/(node_version|NODE_VERSION)\s*=\s*"([^"]+)"/)?.[2]?.trim();
  if (raw) {
    const norm = normalizeNode(raw);
    if (norm) return { file: rel, raw, norm };
  }
  return null;
}

/**
 * Normalize a raw Node version for comparison: strip a leading `v`, zero-pad the
 * patch component to 2 digits. "20" → "20.0.00"; "v20" → "20.0.00";
 * "20.11" → "20.11.00"; "v20.11.5" → "20.11.05"; "20.11.5" → "20.11.05".
 * Returns null if it isn't a numeric version at all — ranges like ">=18.0.0"
 * and "latest" are not declarations.
 */
export function normalizeNode(raw: string): string | null {
  const s = raw.trim().replace(/^v/i, "");
  // v, major(.minor(.patch))? — a bare major ("18", "20") is a valid declaration
  // (Docker `FROM node:18` / package.json "engines": { "node": "20" }).
  const m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(s);
  if (!m) return null;
  const major = m[1]!;
  const minor = m[2] ?? "0";
  const patch = (m[3] ?? "").padStart(2, "0");
  return `${major}.${minor}.${patch}`;
}

/** Collect every Node-version declaration in the project, grouped by location. */
export function collectNodeDecls(projectPath: string): NodeDecl[] {
  const decls: NodeDecl[] = [];
  const pkg = readPackageJsonEngines(projectPath);
  if (pkg) decls.push(pkg);
  const df = readDockerfileNode(projectPath);
  if (df) decls.push(df);
  const fly = readFlyTomlNode(projectPath);
  if (fly) decls.push(fly);
  const webSrc = readWebSrcNode(projectPath);
  for (const d of webSrc.values()) decls.push(d);
  return decls;
}

/**
 * Pure: the list of declarations → Finding[]. No I/O. Encodes the three cases:
 *   • all agree → [] (pass)
 *   • drift → one finding per offending file (declared value + expected value)
 *   • missing location(s) while others declare → one finding naming each missing file
 */
export function parseNodeDrift(decls: NodeDecl[]): Finding[] {
  const findings: Finding[] = [];

  // Which of the four "canonical" locations declared something?
  const canonical = ["package.json", "Dockerfile", "fly.toml"] as const;
  const declaredCanonical = canonical.filter((f) => decls.some((d) => d.file === f));
  const missingCanonical = canonical.filter((f) => !decls.some((d) => d.file === f));

  // web/src-derived declarations are extra pins; they must also agree.
  const webSrcDecls = decls.filter((d) => /^web\//.test(d.file) || /^src\//.test(d.file));

  // Case: something declared, but a canonical root location is missing its declaration.
  // A web/src runtime pin is the project's runtime declaration: when one exists, the
  // missing-root check is satisfied and only AGREEMENT is enforced (a nested
  // web/Dockerfile + package.json that agree form a consistent, complete set).
  if (decls.length > 0 && webSrcDecls.length === 0) {
    for (const f of missingCanonical) {
      findings.push({
        tool: "engines",
        ruleId: "missing-node-version",
        severity: "high",
        file: f,
        message: `No Node.js version declared in ${f}, but ${decls.length} other declaration(s) do. Declare ONE Node version here and make every location agree.`,
      });
    }
  }

  // Case: all absent → nothing to check (no findings).
  if (decls.length === 0) return findings;

  // Group by normalized value; the majority-ish "expected" is the declared value
  // that the most files agree on. If there's a tie, the FIRST declared value wins
  // as expected (deterministic).
  const byNorm = new Map<string, NodeDecl[]>();
  for (const d of decls) {
    const arr = byNorm.get(d.norm) ?? [];
    arr.push(d);
    byNorm.set(d.norm, arr);
  }
  if (byNorm.size <= 1) return findings; // all agree (or all identical) → no drift

  // Expected = the norm with the most declarations; tie broken by first-seen.
  let expectedNorm = "";
  let bestCount = -1;
  for (const [norm, arr] of byNorm) {
    if (arr.length > bestCount) {
      bestCount = arr.length;
      expectedNorm = norm;
    }
  }
  const expectedLabel = humanizeNode(expectedNorm);

  // Every declaration whose norm != expected is an offender.
  const offenders = decls.filter((d) => d.norm !== expectedNorm);
  for (const d of offenders) {
    findings.push({
      tool: "engines",
      ruleId: "node-version-drift",
      severity: "high",
      file: d.file,
      message: `Declares Node ${humanizeNode(d.norm)}, but the agreed version is ${expectedLabel}. Make every Node declaration agree on a single version.`,
    });
  }
  return findings;
}

/** Render a normalized version ("20.11.05") back to a human form ("20.11.5"). */
function humanizeNode(norm: string): string {
  const [major, minor, patch] = norm.split(".");
  const patchShort = patch!.replace(/^0/, "");
  return `${major}.${minor}.${patchShort || "0"}`;
}

/** Run the engines gate against `projectPath` and return a verdict. */
export async function runEngines(
  projectPath: string,
  ranAt: string = new Date().toISOString(),
): Promise<GateVerdict> {
  const absPath = resolve(projectPath);
  const decls = collectNodeDecls(absPath);
  const findings = parseNodeDrift(decls);
  return verdictOf("engines", findings, ranAt);
}

export const enginesGate: Gate = { name: "engines", run: (p: string) => runEngines(p) };
