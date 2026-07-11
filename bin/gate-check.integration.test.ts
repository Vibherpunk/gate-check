/**
 * Standalone smoke test: spawns `bin/gate-check.ts` itself as a real subprocess (not just
 * calling `runGate` in-process) against a vendored, zero-VibeHard-context fixture — no
 * `.vibehard/` state, no Supabase, no dependencies. Proves the package is genuinely usable
 * outside VibeHard: its own CLI, its own fixture, real sast/secrets/depvuln/rls/migrate/verify.
 *
 * Guarded behind VIBEHARD_INTEGRATION — needs semgrep/gitleaks/trivy/npm on PATH (the same
 * tools every other `*.integration.test.ts` in this package already assumes). Run:
 *
 *   VIBEHARD_INTEGRATION=1 bun test gate-check.integration
 */
import { afterEach, describe, expect, test } from "bun:test";
import { rmSync } from "node:fs";
import { join } from "node:path";

const FIXTURE = join(import.meta.dir, "..", "fixtures", "plain-app");
const BIN = join(import.meta.dir, "gate-check.ts");
const run = process.env.VIBEHARD_INTEGRATION ? describe : describe.skip;

afterEach(() => {
  // build/lock artifacts the real gate chain writes into the fixture — gitignored, but clean
  // up anyway so repeat runs start from the same state.
  for (const d of ["dist", ".gate", "node_modules"]) rmSync(join(FIXTURE, d), { recursive: true, force: true });
});

run("standalone gate-check CLI (real subprocess, no VibeHard in the import graph)", () => {
  test("gate <plain-app> — real gates run and pass; no-spec gates report n/a; exits 0", async () => {
    const lockDir = join(FIXTURE, ".host-lock-smoke");
    const proc = Bun.spawnSync(["bun", BIN, "gate", FIXTURE], {
      env: { ...process.env, VIBEHARD_HOST_LOCK_DIR: lockDir },
      stdout: "pipe",
      stderr: "pipe",
    });
    rmSync(lockDir, { recursive: true, force: true });
    const out = `${proc.stdout?.toString() ?? ""}${proc.stderr?.toString() ?? ""}`;

    expect(proc.exitCode, `gate-check exited ${proc.exitCode}, output:\n${out}`).toBe(0);
    // real, deterministic gates ran and found nothing to block on
    for (const gate of ["sast", "secrets", "depvuln", "rls", "migrate", "verify"]) {
      expect(out).toContain(`── ${gate} → PASS (0 blocking) ──`);
    }
    // no .vibehard/spec.json in the fixture → these correctly report n/a, not a vacuous pass
    for (const gate of ["rls-enforce", "compliance", "pii", "prod-readiness", "proptest", "completeness"]) {
      expect(out).toContain(`── ${gate} → N/A (0 blocking) ──`);
    }
    expect(out).toContain("✅ PASS — deploy allowed");
  }, 180_000);
});
