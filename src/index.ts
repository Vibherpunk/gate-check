/**
 * Gate pipeline + deploy sentinel — runs the registered gates against a project,
 * aggregates verdicts, and (for deploy) writes the unskippable sentinel ONLY
 * when every gate passes. Engine-blind: it takes a directory of code, regardless
 * of what produced it. The deploy verdict is deterministic with zero LLM in the
 * path (PROJECT_BRIEF.md §11 "Deploy verdict", §13).
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { rm } from "node:fs/promises";
import { verdictOf, type Gate, type GateVerdict } from "./types.ts";
import { sastGate } from "./sast.ts";
import { secretsGate } from "./secrets.ts";
import { depvulnGate } from "./depvuln.ts";
import { rlsGate } from "./rls.ts";
import { complianceGate } from "./compliance.ts";
import { piiGate } from "./pii.ts";
import { prodReadinessGate } from "./prod-readiness.ts";
import { verifyGate, fastVerifyGate } from "./verify.ts";
import { completenessGate } from "./completeness.ts";
import { migrateGate } from "./migrate.ts";
import { rlsEnforceGate } from "./rls-enforce.ts";
import { proptestGate } from "./proptest.ts";

/** The default gate chain. Source scanners run FIRST, on authored source; verify runs
 *  LAST because it builds the app (creating .next/dist/…) — keeping derived output out
 *  of the source scans (§11, §19). compliance and prod-readiness are
 *  classification/rigor-driven: a no-op unless the app's spec was persisted by the
 *  front-half, so they never fire on a project that didn't go through it. */
export const GATES: Gate[] = [sastGate, secretsGate, depvulnGate, rlsGate, migrateGate, rlsEnforceGate, complianceGate, piiGate, prodReadinessGate, proptestGate, verifyGate, completenessGate];

/** The FAST chain for the inner fix loop: same gates, but verify is the cheap in-place-build
 *  proxy (seconds, not the minutes of clean-room + container + boot probes). Iterate on this;
 *  the full GATES run ONCE at convergence to confirm the real artifact + no regression. */
export const FAST_GATES: Gate[] = [sastGate, secretsGate, depvulnGate, rlsGate, migrateGate, rlsEnforceGate, complianceGate, piiGate, prodReadinessGate, proptestGate, fastVerifyGate];

/** Relative path of the "all gates passed" sentinel within a project. */
export const SENTINEL_REL = ".gate/HARD_VERIFY_PASS";

/** Per-process fallback when VIBEHARD_SENTINEL_SECRET is unset (CLI/dev/test). audit3 M-4: the old
 *  fallback was a COMMITTED literal ("dev-sentinel-insecure"), a publicly-known key anyone could use to
 *  forge a sentinel. A random per-process key removes that: stamp+verify within one process (the real
 *  gate→deploy flow, and tests) still match, while a forged sentinel can't be signed by an attacker who
 *  doesn't know the key. Cross-process without the env var fails verification → fail-CLOSED (deploy
 *  blocked), never fail-open. Set VIBEHARD_SENTINEL_SECRET for stable cross-process verification. */
const FALLBACK_SENTINEL_KEY = randomBytes(32).toString("hex");

/** HMAC-sign a sentinel payload. Key = VIBEHARD_SENTINEL_SECRET, else a per-process random key.
 *  Message = "<projectPath>\n<timestamp>" so a sentinel is bound to exactly one project directory:
 *  copying it into a sibling workspace fails verification (C3 fix). */
function sentinelMac(projectPath: string, timestamp: string): string {
  const secret = process.env.VIBEHARD_SENTINEL_SECRET || FALLBACK_SENTINEL_KEY;
  return createHmac("sha256", secret).update(`${projectPath}\n${timestamp}`).digest("hex");
}

/** Verify the sentinel's HMAC. Fails closed: any missing/malformed/wrong-key content → false. */
export function verifySentinel(projectPath: string): boolean {
  const sentinelPath = join(projectPath, SENTINEL_REL);
  if (!existsSync(sentinelPath)) return false;
  try {
    const [timestamp, mac] = readFileSync(sentinelPath, "utf8").trim().split("\n");
    if (!timestamp || !mac) return false;
    const expected = sentinelMac(projectPath, timestamp);
    return timingSafeEqual(Buffer.from(mac, "hex"), Buffer.from(expected, "hex"));
  } catch {
    return false; // fail-closed: bad read / wrong length / corrupted → deny
  }
}

export interface PipelineResult {
  verdicts: GateVerdict[];
  passed: boolean;
}

export interface DeployResult extends PipelineResult {
  /** Absolute path to the sentinel if written (passed); null if deploy is blocked. */
  sentinel: string | null;
}

export async function runGate(projectPath: string, gates: Gate[] = GATES, onVerdict?: (v: GateVerdict) => void): Promise<PipelineResult> {
  const verdicts: GateVerdict[] = [];
  for (const g of gates) {
    let v: GateVerdict;
    try {
      v = await g.run(projectPath);
    } catch (e) {
      // C-5 (audit2) fail-closed: a gate that THROWS (e.g. Bun.spawnSync raises "Executable not found
      // in $PATH" when docker/trivy/semgrep/gitleaks is missing — a throw, not a non-zero exit) must
      // never escape the loop and crash the pipeline into an unverified state. Convert it to a BLOCKING
      // verdict so the build is held, not silently shipped.
      const message = `the ${g.name} gate crashed (${e instanceof Error ? e.message : String(e)}) — failing closed (§11): a gate that can't run must block, never pass`;
      v = verdictOf(g.name, [{ tool: g.name, ruleId: "gate-crashed", severity: "critical", file: projectPath, message }], new Date().toISOString());
    }
    onVerdict?.(v); // surface each gate's result the moment it lands (live per-gate progress)
    verdicts.push(v);
  }
  // A deploy is allowed when no gate BLOCKS *and* at least one gate did substantive work (status
  // "pass"). B3 (audit2): an app where EVERY gate is "n/a" was never actually verified — nothing
  // applied — so it must NOT stamp the sentinel and ship vacuously. "n/a" never blocks, but a board
  // of all-n/a is not a pass.
  const noBlocks = verdicts.every((v) => v.status === "pass" || v.status === "n/a");
  const anySubstantive = verdicts.some((v) => v.status === "pass");
  return { verdicts, passed: noBlocks && anySubstantive };
}

/**
 * The ratchet, in one place: write the sentinel iff `passed`, else remove a stale
 * one so a prior pass can never authorize a now-failing build. Shared by the
 * deploy gate and the escalation resume path so there is exactly one sentinel writer.
 */
export async function stampSentinel(projectPath: string, passed: boolean): Promise<string | null> {
  const sentinel = join(projectPath, SENTINEL_REL);
  if (passed) {
    const ts = new Date().toISOString();
    const mac = sentinelMac(projectPath, ts);
    await Bun.write(sentinel, `${ts}\n${mac}\n`);
    return sentinel;
  }
  await rm(sentinel, { force: true });
  return null;
}

/**
 * The deploy gate. Runs the chain and stamps the sentinel ONLY if every gate
 * passes. Nothing deploys without this sentinel.
 */
export async function deployGate(projectPath: string, gates: Gate[] = GATES): Promise<DeployResult> {
  const result = await runGate(projectPath, gates);
  return { ...result, sentinel: await stampSentinel(projectPath, result.passed) };
}

// ── Public barrel ──────────────────────────────────────────────────────────────────────────
// The gate contract, re-exported here for convenience (also the package's own `./types.ts`).
export type { Finding, GateVerdict, Gate, Severity } from "./types.ts";
export { isBlocking, verdictOf, notApplicable } from "./types.ts";

// Named exports other subsystems reach for directly, not just the aggregate GATES/runGate —
// preserved so a consumer that already imports one of these by name needs no changes at all.
export { DERIVED_DIRS, hasAuthoredSource, relativizeFinding } from "./scan-scope.ts";
export { parseBuildErrors } from "./build-errors.ts";
export { readAppSources, runRls, rlsGate } from "./rls.ts";
export { runRlsEnforcement, rlsEnforceGate, type EnforceOptions } from "./rls-enforce.ts";
export { installStale, safeToolEnv, isUp, runVerify, runVerifyFast, createVerifyGate, createFastVerifyGate, type VerifyDeps } from "./verify.ts";
export { sastGate } from "./sast.ts";
export { secretsGate } from "./secrets.ts";
export { depvulnGate } from "./depvuln.ts";
export { migrateGate, runMigrate, SUPABASE_STUBS, neutralize, extensionsIn, type MigrateOptions } from "./migrate.ts";
export { complianceGate } from "./compliance.ts";
export { piiGate } from "./pii.ts";
export { prodReadinessGate } from "./prod-readiness.ts";
export { proptestGate } from "./proptest.ts";
export { runCompleteness, createCompletenessGate, type CompletenessOptions } from "./completeness.ts";

// The optional sandbox seam (verify.ts's Fly-equivalent injection points) and the optional LLM
// seam (completeness.ts's functional reviewer) — a host application wires real implementations
// in via these shapes; gate-check has no default for either.
export type { HostProvider, RunSandboxFn, RunExecSandboxFn, SandboxResult, ExecSandboxResult } from "./sandbox-seam.ts";
export { llmFunctionalReviewer, coerceChecks, summarize, FunctionalReviewUnavailable, type FunctionalReviewer, type FunctionalReviewOptions, type ModelFactory as FunctestModelFactory, type LlmConfig as FunctestLlmConfig, type CheckStatus, type FunctionalCheck } from "./functest.ts";

// The vendored spec/backend-model/proptest-validate contracts (compliance/pii/prod-readiness/
// verify/rls-enforce/proptest's inputs) — re-exported for a host application constructing
// `.vibehard/spec.json`-equivalent state or a `DataModel` to pass to `runRlsEnforcement`.
export type { SensitiveClass, Tenancy, DeployTarget, Rigor, DataEntity, Spec } from "./spec-contract.ts";
export { isSensitive, decideRigor, coerceSpec } from "./spec-contract.ts";
export type { DataModel, Entity, Field, FieldType } from "./backend-model.ts";
export { coerceDataModel } from "./backend-model.ts";

// Shared subprocess infra (used internally by sast/secrets/depvuln/verify) — re-exported since
// VibeHard's autofix/substrate layers also serialize their own heavy host work through the same
// budget + lock, matching what they borrowed from `src/util/` before this extraction.
export { SUBPROCESS_TIMEOUT_MS } from "./timeouts.ts";
export { withHostLock } from "./host-lock.ts";

// The gate-verdict printer — shared by VibeHard's `vibehard gate`/`vibehard deploy` CLI and this
// package's own standalone `gate-check` CLI (bin/gate-check.ts).
export { printReport, type ReportResult, type PrintReportOptions } from "./report.ts";
