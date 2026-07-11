/**
 * M1 Definition of Done (PROJECT_BRIEF.md §9), end to end with the REAL
 * scanners (semgrep + gitleaks in pinned containers), the static RLS check, and
 * the launch probe. Guarded behind VIBEHARD_INTEGRATION because it needs Docker +
 * Node and is slow; default `bun test` stays fast. Run with:
 *
 *   VIBEHARD_INTEGRATION=1 bun test deploy.integration
 */
import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { deployGate } from "./index.ts";

const FIXTURES = join(import.meta.dir, "..", "fixtures");
const run = process.env.VIBEHARD_INTEGRATION ? describe : describe.skip;

run("deploy gate — M1 DoD (real scanners)", () => {
  test("BLOCKS the vulnerable app and writes no sentinel", async () => {
    const r = await deployGate(join(FIXTURES, "vulnerable"));
    expect(r.passed).toBe(false);
    expect(r.sentinel).toBeNull();
    const blocked = r.verdicts.filter((v) => v.status === "block").map((v) => v.gate);
    expect(blocked).toContain("sast");
    expect(blocked).toContain("secrets");
    expect(blocked).toContain("rls");
  }, 120_000);

  test("PASSES the remediated app and writes the sentinel", async () => {
    const r = await deployGate(join(FIXTURES, "remediated"));
    expect(r.passed).toBe(true);
    expect(r.sentinel).not.toBeNull();
    for (const v of r.verdicts) expect(v.status).toBe("pass");
  }, 120_000);
});
