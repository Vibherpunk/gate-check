/**
 * dep-vuln gate — end to end with REAL trivy. Guarded behind VIBEHARD_INTEGRATION (needs
 * `trivy` on PATH — a native binary as of 2026-07-06, not Docker; see TRIVY_VERSION in
 * depvuln.ts. First run downloads the vuln DB into TRIVY_CACHE_DIR, then it's cached). Run:
 *
 *   VIBEHARD_INTEGRATION=1 bun test depvuln.integration
 */
import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { runDepVuln } from "./depvuln.ts";

const FIXTURES = join(import.meta.dir, "..", "fixtures");
const run = process.env.VIBEHARD_INTEGRATION ? describe : describe.skip;

run("dep-vuln gate (real trivy)", () => {
  test("BLOCKS a project with a known-vulnerable dependency (lodash 4.17.4)", async () => {
    const v = await runDepVuln(join(FIXTURES, "vuln-deps"));
    expect(v.status).toBe("block");
    expect(v.blocking).toBeGreaterThan(0);
    // a real CVE finding from trivy, plain CVE ruleId
    expect(v.findings.some((f) => f.tool === "trivy" && /^CVE-/.test(f.ruleId))).toBe(true);
    expect(v.findings.some((f) => f.message.includes("lodash"))).toBe(true);
    expect(v.findings.every((f) => f.ruleId !== "scan-failed")).toBe(true); // scan actually ran
  }, 180_000);

  test("PASSES a project with no dependencies (no manifests → nothing to scan)", async () => {
    const v = await runDepVuln(join(FIXTURES, "remediated"));
    expect(v.status).toBe("pass");
    expect(v.blocking).toBe(0);
  }, 180_000);
});
