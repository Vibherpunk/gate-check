/**
 * The property-test gate (EPIC #53): runs the per-requirement fast-check property tests that
 * codegen generated into tests/properties/ (src/proptest/). Each file asserts one PRD
 * requirement's acceptance criteria over ALL inputs (fixed seed — deterministic), so this gate
 * is a REGRESSION RATCHET: the tests pass when generated, and any later fix round or change
 * request that breaks a covered acceptance criterion blocks here with the requirement named.
 *
 * Anti-gaming, three layers deep (the differentiator vs advisory-only tooling):
 *   1. a vacuous/skipped/neutered test file is itself a BLOCKING finding (checked here, pure);
 *   2. anti-tamper hashes every property test before a fix round — any edit/delete is a
 *      rejected tamper (src/autofix/anti-tamper.ts), so the fixer can only fix the APP;
 *   3. the runner is `bun test` on the platform's own runtime — the app's package.json scripts
 *      (which the fixer CAN edit) are never in the loop.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { notApplicable, verdictOf, type Finding, type Gate } from "./types.ts";
import { PROPTEST_DIR, propTestVacuityReason, requirementIdOf } from "./proptest-validate.ts";
import { safeToolEnv } from "./verify.ts";

/** Bounded like CLEAN_TIMEOUT_MS in verify.ts — a hung property (infinite loop in app code
 *  under a generated input) must block with a finding, not hang the pipeline. */
export const PROPTEST_TIMEOUT_MS = 120_000;

export interface PropRunResult {
  exitCode: number;
  output: string;
}
/** Injectable subprocess seam so the verdict mapping is unit-testable without a real app. */
export type PropRunner = (cmd: string[], cwd: string, env: Record<string, string>, timeoutMs: number) => PropRunResult;

const defaultRunner: PropRunner = (cmd, cwd, env, timeoutMs) => {
  const p = Bun.spawnSync(cmd, { cwd, env, stdout: "pipe", stderr: "pipe", timeout: timeoutMs });
  return { exitCode: p.exitCode ?? 1, output: `${p.stdout?.toString() ?? ""}${p.stderr?.toString() ?? ""}` };
};

const f = (ruleId: string, file: string, message: string): Finding => ({ tool: "proptest", ruleId, severity: "high", file, message });

export function listPropTestFiles(projectPath: string): string[] {
  const dir = join(projectPath, PROPTEST_DIR);
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir).filter((n) => n.endsWith(".test.ts")).sort();
  } catch {
    return [];
  }
}

export function propTestGateRun(projectPath: string, now: string, runner: PropRunner = defaultRunner): ReturnType<Gate["run"]> {
  const files = listPropTestFiles(projectPath);
  // No property tests → nothing to check. n/a on purpose (never a vacuous "pass", audit H4);
  // deletion of the whole directory is caught by anti-tamper, not here.
  if (!files.length) return Promise.resolve(notApplicable("proptest", now));

  const findings: Finding[] = [];
  for (const name of files) {
    const rel = join(PROPTEST_DIR, name);
    let content = "";
    try {
      content = readFileSync(join(projectPath, rel), "utf8");
    } catch {
      findings.push(f("vacuous-property-test", rel, "The property test file exists but cannot be read."));
      continue;
    }
    const reason = propTestVacuityReason(content);
    if (reason) {
      findings.push(
        f(
          "vacuous-property-test",
          rel,
          `This property test no longer tests anything: ${reason}. Property tests are generated from the PRD's acceptance criteria and are read-only for fixes — restore the test and fix the APP behavior instead.`,
        ),
      );
    }
  }
  // A neutered test must block on its own — running the remainder could go green and mask it.
  if (findings.length) return Promise.resolve(verdictOf("proptest", findings, now));

  const env = safeToolEnv(projectPath);
  // fast-check is declared as a devDependency at generation time (or, when the app's own tree
  // wouldn't install, isolated under tests/properties/node_modules — bun resolves from the
  // nearest node_modules to the test file, so either location works); a fix round may have
  // left node_modules stale (same reason verify.ts ensureInstalled exists).
  if (!existsSync(join(projectPath, "node_modules", "fast-check")) && !existsSync(join(projectPath, PROPTEST_DIR, "node_modules", "fast-check"))) {
    const install = runner(["npm", "install", "--no-audit", "--no-fund", "--ignore-scripts"], projectPath, env, PROPTEST_TIMEOUT_MS);
    if (install.exitCode !== 0) {
      return Promise.resolve(
        verdictOf("proptest", [f("proptest-install-failed", "package.json", `Installing test dependencies failed (exit ${install.exitCode}) — the property suite cannot run: ${install.output.slice(-500)}`)], now),
      );
    }
  }

  const run = runner(["bun", "test", PROPTEST_DIR], projectPath, env, PROPTEST_TIMEOUT_MS);
  if (run.exitCode === 0) return Promise.resolve(verdictOf("proptest", [], now));

  // Attribute failures to requirement(s) via each file's @requirement header. bun test prints
  // a per-file section header ("path/to/x.test.ts:") followed by its (pass)/(fail) lines —
  // walk the sections so only files that actually FAILED are attributed. Attribution is
  // best-effort display; an unattributable failure still blocks via the aggregate finding.
  const tail = run.output.slice(-1200);
  const failedFiles = new Set<string>();
  let currentFile: string | null = null;
  for (const line of run.output.split("\n")) {
    const header = /([\w./-]+\.test\.tsx?):?\s*$/.exec(line.trim());
    if (header) currentFile = header[1] ?? null;
    if (/^\s*\(fail\)/.test(line) && currentFile) failedFiles.add(currentFile.split("/").pop()!);
  }
  for (const name of files) {
    if (!failedFiles.has(name)) continue;
    const rel = join(PROPTEST_DIR, name);
    let reqId: string | null = null;
    try {
      reqId = requirementIdOf(readFileSync(join(projectPath, rel), "utf8"));
    } catch {
      /* attribution only */
    }
    findings.push(
      f(
        "property-violated",
        rel,
        `A property test${reqId ? ` for requirement ${reqId}` : ""} FAILED — the app violates an acceptance criterion it previously satisfied. Fix the app behavior; the test itself is generated from the PRD and read-only. Output tail:\n${tail}`,
      ),
    );
  }
  if (!findings.length) {
    findings.push(f("property-violated", PROPTEST_DIR, `The property test suite failed (exit ${run.exitCode}). Output tail:\n${tail}`));
  }
  return Promise.resolve(verdictOf("proptest", findings, now));
}

export const proptestGate: Gate = {
  name: "proptest",
  run: (projectPath) => propTestGateRun(projectPath, new Date().toISOString()),
};
