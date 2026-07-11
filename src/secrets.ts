/**
 * Secrets gate — real gitleaks (pinned container). Pure parser + container run,
 * same shape as the SAST gate. Ported from ~/dev/gate-proof/gates/secrets.sh.
 * Any leaked secret is blocking regardless of severity (see types.isBlocking).
 */
import { join, resolve } from "node:path";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import type { Finding, GateVerdict } from "./types.ts";
import { verdictOf } from "./types.ts";
import { hasAuthoredSource, relativizeFinding } from "./scan-scope.ts";
import { SUBPROCESS_TIMEOUT_MS } from "./timeouts.ts";
import { withHostLock } from "./host-lock.ts";

/** The exact gitleaks version the production image installs natively (Dockerfile) — see the
 *  same 2026-07-06 note in sast.ts (SEMGREP_VERSION): docker was never available on the
 *  platform container, so this gate crash-blocked every build; native binary replaces it. */
export const GITLEAKS_VERSION = "v8.18.4";

/** Pure: gitleaks JSON (an array of leaks) → Finding[]. No I/O. */
export function parseGitleaks(raw: unknown): Finding[] {
  const items = Array.isArray(raw) ? raw : [];
  return items.map((r): Finding => {
    const g = r as { RuleID?: string; Description?: string; File?: string; StartLine?: number };
    return {
      tool: "gitleaks",
      ruleId: String(g.RuleID ?? "unknown"),
      severity: "high",
      file: String(g.File ?? ""),
      line: g.StartLine,
      message: String(g.Description ?? "leaked secret").trim(),
    };
  });
}

/** Run gitleaks NATIVELY (no container — see GITLEAKS_VERSION) against `projectPath` and
 *  return a verdict. Reads source as data only (never executes it), so on-host is safe —
 *  same boundary sast/verify document. */
export async function runSecrets(
  projectPath: string,
  ranAt: string = new Date().toISOString(),
): Promise<GateVerdict> {
  const absPath = resolve(projectPath);
  // §11 fail-closed: no authored source (only derived/build output, or empty) →
  // with the path allowlist active, gitleaks would scan nothing → false PASS.
  if (!hasAuthoredSource(absPath)) {
    return verdictOf(
      "secrets",
      [{ tool: "gitleaks", ruleId: "scan-failed", severity: "critical", file: absPath, message: "Secret scan saw no authored source to scan (only derived/build output) — failing closed (§11)." }],
      ranAt,
    );
  }
  const rulesDir = join(import.meta.dir, "rules");
  // gitleaks can't write its report to `/dev/stdout` outside a container (found 2026-07-06:
  // "open /dev/stdout: permission denied" — that trick only worked via Docker's own stdio
  // wiring). A real temp file is the portable equivalent; read it back, always clean it up.
  const reportDir = mkdtempSync(join(tmpdir(), "vibehard-gitleaks-"));
  const reportPath = join(reportDir, "report.json");
  let stdout = "";
  let stderr = "";
  let exitCode = -1;
  try {
    // cwd=absPath + --source=. — same reasoning as sast.ts's fix (2026-07-07): a tenant
    // workspace lives under a .vibehard-named ancestor (the platform's own state root), so an
    // absolute source keeps that name in view for any path-based exclusion to (mis)match.
    // gitleaks's allowlist regex empirically matches relative to --source already (verified:
    // secrets passed on the exact workspace that broke sast), so this is defense-in-depth to
    // keep the two gates' invocation shape identical, not a fix for an observed failure here.
    // EPIC #32: same host-lock discipline as sast.ts — gitleaks is a real filesystem walk +
    // regex scan, heavy enough to contend for CPU when another build's scan runs concurrently.
    const proc = await withHostLock(
      () =>
        Bun.spawnSync(
          [
            "gitleaks", "detect", "--source=.", "--no-git",
            `--config=${join(rulesDir, "gitleaks.toml")}`, // keep default rules; allowlist derived dirs (§11)
            "--report-format", "json", "--report-path", reportPath,
          ],
          { cwd: absPath, timeout: SUBPROCESS_TIMEOUT_MS },
        ),
      { note: (m) => console.error(`[secrets] ${m}`) },
    );
    exitCode = proc.exitCode ?? -1;
    stderr = proc.stderr?.toString() ?? "";
    try {
      stdout = readFileSync(reportPath, "utf8");
    } catch {
      stdout = ""; // gitleaks errored before writing a report — interpretGitleaks fails closed on this
    }
  } finally {
    rmSync(reportDir, { recursive: true, force: true });
  }
  const findings = interpretGitleaks(stdout, exitCode, stderr, absPath).map((f) => ({ ...f, file: relativizeFinding(absPath, f.file) }));
  return verdictOf("secrets", findings, ranAt);
}

/**
 * Pure: a gitleaks run's output → Finding[], failing CLOSED. gitleaks exits
 * 0 = clean, 1 = leaks found, >1 = error. An error (or non-array output) means
 * the scan did not run — return a CRITICAL `scan-failed` finding (which blocks),
 * never a silent pass. (PROJECT_BRIEF §11 fail-closed invariant.)
 */
export function interpretGitleaks(
  stdout: string,
  exitCode: number,
  stderr: string,
  target: string,
): Finding[] {
  if (exitCode > 1) {
    return [
      {
        tool: "gitleaks",
        ruleId: "scan-failed",
        severity: "critical",
        file: target,
        message: `Secret scan did not run (exit ${exitCode}) — failing closed. ${stderr.trim().slice(0, 200)}`.trim(),
      },
    ];
  }
  let json: unknown;
  try {
    json = JSON.parse(stdout || "[]");
  } catch {
    json = null;
  }
  if (!Array.isArray(json)) {
    return [
      {
        tool: "gitleaks",
        ruleId: "scan-failed",
        severity: "critical",
        file: target,
        message: `Secret scan produced no valid report (exit ${exitCode}) — failing closed.`,
      },
    ];
  }
  return parseGitleaks(json);
}

export const secretsGate = { name: "secrets", run: (p: string) => runSecrets(p) };
