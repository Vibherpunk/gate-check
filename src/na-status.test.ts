import { describe, expect, test } from "bun:test";
import { runGate } from "./index.ts";
import { notApplicable, verdictOf, type Finding, type Gate } from "./types.ts";

const naGate: Gate = { name: "classify", run: async () => notApplicable("classify", "t") };
const passGate: Gate = { name: "scan", run: async () => verdictOf("scan", [], "t") };
const high: Finding = { tool: "z", ruleId: "r", severity: "high", file: "f", message: "m" };
const blockGate: Gate = { name: "rls", run: async () => verdictOf("rls", [high], "t") };

describe("B3 — n/a status: honest, non-blocking, never a vacuous pass", () => {
  test("notApplicable is status 'n/a' with zero findings/blocking — distinct from a real pass", () => {
    const v = notApplicable("g", "t");
    expect(v.status).toBe("n/a");
    expect(v.blocking).toBe(0);
    expect(v.findings).toEqual([]);
  });

  test("a deploy is ALLOWED when gates are pass+n/a — but the n/a is reported as n/a, not pass", async () => {
    const r = await runGate("/x", [passGate, naGate]);
    expect(r.passed).toBe(true); // n/a does not block
    expect(r.verdicts.map((v) => v.status)).toEqual(["pass", "n/a"]); // and is honestly labelled (audit H4)
  });

  test("a real block still blocks even alongside n/a gates", async () => {
    const r = await runGate("/x", [naGate, blockGate]);
    expect(r.passed).toBe(false);
  });

  test("audit2 B3: an ALL-n/a board is NOT a pass — nothing was verified, so don't ship vacuously", async () => {
    const r = await runGate("/x", [naGate, { name: "classify2", run: async () => notApplicable("classify2", "t") }]);
    expect(r.passed).toBe(false); // no block, but no substantive pass either → not deployable
    expect(r.verdicts.every((v) => v.status === "n/a")).toBe(true);
  });
});
