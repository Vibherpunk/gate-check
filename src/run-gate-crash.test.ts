import { describe, expect, test } from "bun:test";
import { runGate } from "./index.ts";
import { verdictOf, type Gate } from "./types.ts";

describe("runGate — C-5 (audit2): a gate that THROWS fails closed, never crashes the pipeline", () => {
  const okGate: Gate = { name: "ok", run: async () => verdictOf("ok", [], "t") };
  const throwingGate: Gate = {
    name: "sast",
    run: async () => {
      throw new Error("Executable not found in $PATH: \"docker\""); // the missing-binary class
    },
  };

  test("a throwing gate becomes a BLOCKING gate-crashed verdict; pipeline does not throw", async () => {
    const r = await runGate("/tmp/whatever", [okGate, throwingGate]);
    expect(r.passed).toBe(false); // fail-closed — not a silent pass
    const crashed = r.verdicts.find((v) => v.gate === "sast");
    expect(crashed?.status).toBe("block");
    expect(crashed?.findings?.[0]?.ruleId).toBe("gate-crashed");
    expect(crashed?.findings?.[0]?.message).toMatch(/Executable not found/);
  });

  test("a sibling gate still runs and reports normally after one crashes", async () => {
    const r = await runGate("/tmp/whatever", [throwingGate, okGate]);
    expect(r.verdicts.map((v) => v.gate)).toEqual(["sast", "ok"]);
    expect(r.verdicts.find((v) => v.gate === "ok")?.status).toBe("pass");
  });
});
