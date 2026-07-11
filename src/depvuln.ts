/**
 * Dependency-vulnerability gate — trivy (pinned container) scanning the project's
 * dependency manifests/lockfiles for known CVEs (PROJECT_BRIEF.md §15 NEXT, §17,
 * §19). Polyglot + container + parse-JSON, same pattern as sast/secrets (§4).
 *
 * Pure parser (`parseTrivy`) + pure fail-closed interpretation (`interpretTrivy`)
 * are unit-tested without a container; the container run is the only I/O. Per the
 * §11 fail-closed invariant, a scan that did NOT run returns a CRITICAL
 * `scan-failed` (which blocks) — never a silent pass.
 */
import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import type { Finding, GateVerdict, Severity } from "./types.ts";
import { verdictOf } from "./types.ts";
import { SUBPROCESS_TIMEOUT_MS } from "./timeouts.ts";
import { withHostLock } from "./host-lock.ts";

const LOCKFILES = ["package-lock.json", "bun.lockb", "bun.lock", "yarn.lock", "pnpm-lock.yaml"];

/** trivy `fs` scans LOCKFILES; a project with declared deps but NO lockfile resolves nothing, so trivy
 *  returns no findings — a SILENT clean pass that never assessed the transitive (install-time) tree
 *  (audit M5). Surface that gap as a non-blocking advisory so "depvuln passed" isn't misread as "no
 *  vulnerable deps" when the truth is "deps weren't fully resolved". */
export function scanGapFindings(projectPath: string): Finding[] {
  const pkgPath = join(projectPath, "package.json");
  if (!existsSync(pkgPath)) return [];
  let deps = 0;
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).length;
  } catch {
    return [];
  }
  if (deps === 0 || LOCKFILES.some((l) => existsSync(join(projectPath, l)))) return [];
  return [{ tool: "depvuln", ruleId: "depscan-incomplete", severity: "medium", file: "package.json", message: `dependency scan INCOMPLETE: ${deps} dependencies are declared but there is no lockfile, so transitive (install-time) CVEs were not assessed. Run an install to generate a lockfile, then re-gate.` }];
}

/** The exact trivy version the production image installs natively (Dockerfile) — see the
 *  same 2026-07-06 note in sast.ts (SEMGREP_VERSION): docker was never available on the
 *  platform container, so this gate crash-blocked every build; native binary replaces it.
 *  Bumped from the old docker-image pin (0.58.1) — that patch tag has no published GitHub
 *  release binary (git tag exists, no release assets; likely a docker-only point release),
 *  so there is nothing to install natively at that exact version. 0.72.0 is current, has
 *  real Linux binaries, and is what this fix was validated against locally end-to-end. */
export const TRIVY_VERSION = "0.72.0";
/** Persist trivy's vuln DB across runs on this host so it's downloaded once, not every scan
 *  (still wiped on a redeploy — no volume — same characteristic the docker named volume had). */
const TRIVY_CACHE_DIR = join(homedir(), ".cache", "vibehard-trivy");

/** trivy severity → our scale (CRITICAL/HIGH block; MEDIUM/LOW are reported, not blocking). */
export function mapTrivySeverity(s: string | undefined): Severity {
  switch ((s ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    default:
      return "low"; // LOW / UNKNOWN
  }
}

/** Pure: trivy `fs` JSON → Finding[]. No I/O. */
export function parseTrivy(raw: unknown): Finding[] {
  const results = (raw as { Results?: unknown[] } | null)?.Results ?? [];
  const findings: Finding[] = [];
  for (const r of results) {
    const target = String((r as { Target?: string }).Target ?? "");
    const vulns = (r as { Vulnerabilities?: unknown[] }).Vulnerabilities ?? [];
    for (const v of vulns ?? []) {
      const x = v as {
        VulnerabilityID?: string;
        PkgName?: string;
        InstalledVersion?: string;
        FixedVersion?: string;
        Severity?: string;
        Title?: string;
      };
      const fix = x.FixedVersion ? `fixed in ${x.FixedVersion}` : "no fix available yet";
      findings.push({
        tool: "trivy",
        ruleId: String(x.VulnerabilityID ?? "unknown"),
        severity: mapTrivySeverity(x.Severity),
        file: target,
        message: `${x.PkgName ?? "?"}@${x.InstalledVersion ?? "?"}: ${String(x.Title ?? "known vulnerability").trim()} (${fix})`,
      });
    }
  }
  return findings;
}

function scanFailed(exitCode: number, stderr: string, target: string): Finding {
  return {
    tool: "trivy",
    ruleId: "scan-failed",
    severity: "critical",
    file: target,
    message: `Dependency scan did not run (exit ${exitCode}) — failing closed. ${stderr.trim().slice(0, 200)}`.trim(),
  };
}

/**
 * Pure: a trivy run → Finding[], failing CLOSED (§11). trivy `fs` exits 0 on a
 * SUCCESSFUL scan whether or not it finds vulns (we do NOT pass --exit-code), and
 * emits `Results: null` for a project with no dependency manifests. So "it ran" is
 * proven by *exit 0 + a valid JSON report object* — NOT by `Results` being an array
 * (requiring that would false-fail a legitimate no-dependency project). A non-zero
 * exit or unparseable output means the scan did not run → CRITICAL `scan-failed`.
 */
export function interpretTrivy(stdout: string, exitCode: number, stderr: string, target: string): Finding[] {
  if (exitCode !== 0) return [scanFailed(exitCode, stderr, target)];
  let json: unknown;
  try {
    json = JSON.parse(stdout);
  } catch {
    json = null;
  }
  if (json === null || typeof json !== "object") return [scanFailed(exitCode, stderr, target)];
  return parseTrivy(json); // Results ?? [] → a clean no-deps scan yields no findings (PASS)
}

/** Run trivy NATIVELY (no container — see TRIVY_VERSION) against `projectPath` and return a
 *  verdict. Reads dependency manifests as data only (never executes anything), so on-host is
 *  safe — same boundary sast/secrets/verify document. */
export async function runDepVuln(
  projectPath: string,
  ranAt: string = new Date().toISOString(),
): Promise<GateVerdict> {
  const absPath = resolve(projectPath);
  // cwd=absPath + target "." — same reasoning as sast.ts's fix (2026-07-07): a tenant
  // workspace lives under a .vibehard-named ancestor (the platform's own state root); trivy's
  // own Target reporting is already relative to the given target (verified: depvuln passed on
  // the exact workspace that broke sast), so this is defense-in-depth, not an observed fix.
  // EPIC #32: same host-lock discipline as sast.ts/secrets.ts — trivy's CVE-database walk is
  // heavy enough to contend for CPU/memory when another build's scan runs concurrently.
  const proc = await withHostLock(
    () =>
      Bun.spawnSync(
        ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln", "--cache-dir", TRIVY_CACHE_DIR, "."],
        { cwd: absPath, timeout: SUBPROCESS_TIMEOUT_MS },
      ),
    { note: (m) => console.error(`[depvuln] ${m}`) },
  );
  const findings = [
    ...interpretTrivy(proc.stdout?.toString() ?? "", proc.exitCode ?? -1, proc.stderr?.toString() ?? "", absPath),
    ...scanGapFindings(absPath), // make a no-lockfile (incomplete) scan VISIBLE, not a silent pass
  ];
  return verdictOf("depvuln", findings, ranAt);
}

export const depvulnGate = { name: "depvuln", run: (p: string) => runDepVuln(p) };
