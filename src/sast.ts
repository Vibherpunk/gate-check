/**
 * SAST gate — real semgrep (pinned container) + the custom CWE-89 rule.
 * The parse step is a pure function (unit-tested); the container run is the
 * only I/O (integration-tested). Ported from ~/dev/gate-proof/gates/sast.sh.
 */
import { join, resolve } from "node:path";
import type { Finding, GateVerdict, Severity } from "./types.ts";
import { verdictOf } from "./types.ts";
import { DERIVED_DIRS, hasAuthoredSource, relativizeFinding } from "./scan-scope.ts";
import { SUBPROCESS_TIMEOUT_MS } from "./timeouts.ts";
import { withHostLock } from "./host-lock.ts";

/** The exact semgrep version the production image installs natively (Dockerfile) — this
 *  constant is documentation, not an invocation parameter; there is no container to pin it
 *  into anymore (found 2026-07-06: the platform container never had `docker`, so this gate
 *  crash-blocked every build; native binary replaces the docker wrapper, same tool/version). */
export const SEMGREP_VERSION = "1.96.0";

/** semgrep severity → our scale (preserves the proof: ERROR blocks). */
export function mapSeverity(s: string | undefined): Severity {
  switch ((s ?? "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    default:
      return "low";
  }
}

/** Pure: semgrep JSON → Finding[]. No I/O. */
export function parseSemgrep(raw: unknown): Finding[] {
  const results = (raw as { results?: unknown[] } | null)?.results ?? [];
  return results.map((r): Finding => {
    const x = r as {
      check_id?: string;
      path?: string;
      start?: { line?: number };
      extra?: { severity?: string; message?: string };
    };
    return {
      tool: "semgrep",
      ruleId: String(x.check_id ?? "unknown"),
      severity: mapSeverity(x.extra?.severity),
      file: String(x.path ?? ""),
      line: x.start?.line,
      message: String(x.extra?.message ?? "").trim(),
    };
  });
}

/** Run semgrep NATIVELY (no container — see SEMGREP_VERSION) against `projectPath` and
 *  return a verdict. Semgrep only READS source as data here; it never executes the app's
 *  code, so running it on-host (rather than sandboxed) carries no more risk than any other
 *  static text scan (src/substrate/fly-sandbox.ts's own header documents this boundary). */
export async function runSast(
  projectPath: string,
  ranAt: string = new Date().toISOString(),
): Promise<GateVerdict> {
  const rulesDir = join(import.meta.dir, "rules");
  const absPath = resolve(projectPath);
  // §11 fail-closed: if there's no authored source (only derived/build output, or
  // empty), excluding the derived set leaves semgrep nothing to scan → false PASS.
  if (!hasAuthoredSource(absPath)) {
    return verdictOf(
      "sast",
      [{ tool: "semgrep", ruleId: "scan-failed", severity: "critical", file: absPath, message: "SAST saw no authored source to scan (only derived/build output) — failing closed (§11)." }],
      ranAt,
    );
  }
  // Gates scan AUTHORED SOURCE, never derived output (else minified framework code
  // in .next/dist/… floods us with false positives).
  const excludes = DERIVED_DIRS.flatMap((d) => ["--exclude", d]);
  // cwd=absPath + target "." — NOT absPath as the target. Found live 2026-07-07 on a real
  // customer build: a tenant workspace lives at .../.vibehard/tenants/<id>/apps/<app> — the
  // platform's OWN state root is itself named .vibehard, so passing the ABSOLUTE workspace
  // path meant `--exclude .vibehard` matched that ANCESTOR directory too (gitignore-style
  // exclude matches a bare name at any depth in the given path) and excluded the ENTIRE
  // target — "SAST scanned 0 files", failing closed, blocking the build on nothing. Scanning
  // "." from cwd=absPath means every candidate path semgrep sees starts INSIDE the workspace;
  // the ambient .vibehard ancestor never appears, so it can't be (mis)matched.
  // EPIC #32: semgrep is the heaviest host-side scanner (a real CPU/memory-bound ruleset
  // eval, not a quick grep) — found live 2026-07-09, it's exactly what failed to even start
  // ("SAST scan did not run (exit -1)") when two builds' scans ran concurrently on one host.
  const proc = await withHostLock(
    () =>
      Bun.spawnSync(
        ["semgrep", "scan", "--quiet", "--json", "--config", join(rulesDir, "sqli.yaml"), "--config", "p/default", ...excludes, "."],
        { cwd: absPath, timeout: SUBPROCESS_TIMEOUT_MS },
      ),
    { note: (m) => console.error(`[sast] ${m}`) },
  );
  const findings = interpretSemgrep(
    proc.stdout?.toString() ?? "",
    proc.exitCode ?? -1,
    proc.stderr?.toString() ?? "",
    absPath,
  ).map((f) => ({ ...f, file: relativizeFinding(absPath, f.file) }));
  return verdictOf("sast", findings, ranAt);
}

/**
 * Pure: a semgrep run's raw output → Finding[], failing CLOSED. A run that did
 * not produce valid semgrep JSON (a `results` array) did not actually scan — so
 * we return a CRITICAL `scan-failed` finding (which blocks), never a silent
 * pass. "Scanner didn't run" must never look like "scanned, clean" — the
 * false-PASS class (PROJECT_BRIEF §11 fail-closed invariant).
 */
/** A semgrep `errors[]` entry that indicates the RULESET/CONFIG failed to load (vs. a single
 *  unparseable target file). When p/default can't load, semgrep still emits valid JSON with an empty
 *  `results` array — a clean-looking PASS over nothing (audit2 C5). */
function isConfigError(e: unknown): boolean {
  const o = e as { level?: string; type?: string; message?: string };
  const text = `${o.type ?? ""} ${o.message ?? ""}`.toLowerCase();
  return /config|ruleset|could not (load|find)|failed to (load|parse)[^.]*\b(rule|config)|no rules?\b|unable to (load|find)/.test(text);
}

function scanFailed(target: string, message: string): Finding {
  return { tool: "semgrep", ruleId: "scan-failed", severity: "critical", file: target, message };
}

export function interpretSemgrep(
  stdout: string,
  exitCode: number,
  stderr: string,
  target: string,
): Finding[] {
  let json: unknown;
  try {
    json = JSON.parse(stdout);
  } catch {
    json = null;
  }
  const ran =
    json !== null && typeof json === "object" && Array.isArray((json as { results?: unknown }).results);
  if (!ran) {
    return [scanFailed(target, `SAST scan did not run (exit ${exitCode}) — failing closed. ${stderr.trim().slice(0, 200)}`.trim())];
  }
  // C5 (audit2): a valid `results` array is NOT proof the scan was real. Inspect what semgrep itself
  // reported — a config/ruleset load failure, or zero files actually scanned (when we already know
  // authored source exists) means it scanned nothing meaningful → fail closed, never a vacuous pass.
  const j = json as { errors?: unknown[]; paths?: { scanned?: unknown[] } };
  const errors = Array.isArray(j.errors) ? j.errors : [];
  const scanned = Array.isArray(j.paths?.scanned) ? (j.paths!.scanned as unknown[]) : null;
  if (scanned !== null && scanned.length === 0) {
    return [scanFailed(target, `SAST scanned 0 files (exit ${exitCode}) — the ruleset failed to load or every path was skipped; failing closed. ${stderr.trim().slice(0, 160)}`.trim())];
  }
  const fatal = errors.filter(isConfigError);
  if (fatal.length) {
    const detail = fatal.map((e) => String((e as { message?: string }).message ?? (e as { type?: string }).type ?? "config error")).join("; ");
    return [scanFailed(target, `SAST ruleset/config failed to load (exit ${exitCode}) — failing closed: ${detail.slice(0, 200)}`)];
  }
  return parseSemgrep(json);
}

export const sastGate = { name: "sast", run: (p: string) => runSast(p) };
