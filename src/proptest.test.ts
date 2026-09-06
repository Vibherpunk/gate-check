import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { propTestGateRun, listPropTestFiles, type PropRunner } from "./proptest.ts";
import { PROPTEST_DIR } from "./proptest-validate.ts";

const NOW = "2026-01-01T00:00:00Z";
const tmps: string[] = [];
afterEach(() => {
  for (const d of tmps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function workspace(): string {
  const d = mkdtempSync(join(tmpdir(), "vibehard-proptest-"));
  tmps.push(d);
  return d;
}

/** A valid property test asserting `clamp` stays within bounds — reqId F1. */
const VALID_TEST = `// @requirement F1
import { test } from "bun:test";
import fc from "fast-check";
import { clamp } from "../../lib/clamp";

test("F1: clamp output is always within [lo, hi]", () => {
  fc.assert(fc.property(fc.integer(), fc.integer({ min: 0, max: 10 }), (x, lo) => {
    const hi = lo + 5;
    const y = clamp(x, lo, hi);
    return y >= lo && y <= hi;
  }), { seed: 42, numRuns: 1000 });
});
`;

function writeApp(dir: string, clampBody: string, testContent: string = VALID_TEST): void {
  mkdirSync(join(dir, "lib"), { recursive: true });
  writeFileSync(join(dir, "lib", "clamp.ts"), clampBody);
  mkdirSync(join(dir, PROPTEST_DIR), { recursive: true });
  writeFileSync(join(dir, PROPTEST_DIR, "f1.test.ts"), testContent);
  // Real fast-check without a real npm install: link the platform's own copy.
  mkdirSync(join(dir, "node_modules"), { recursive: true });
  symlinkSync(join(import.meta.dir, "..", "node_modules", "fast-check"), join(dir, "node_modules", "fast-check"), "dir");
}

describe("proptest gate — verdict mapping (stub runner)", () => {
  test("no tests/properties dir → n/a, never a vacuous pass (audit H4)", async () => {
    const v = await propTestGateRun(workspace(), NOW);
    expect(v.status).toBe("n/a");
  });

  test("a vacuous test file BLOCKS without running the suite", async () => {
    const dir = workspace();
    mkdirSync(join(dir, PROPTEST_DIR), { recursive: true });
    writeFileSync(join(dir, PROPTEST_DIR, "f1.test.ts"), VALID_TEST.replace("fc.assert", "console.log")); // neutered
    let ran = false;
    const runner: PropRunner = () => ((ran = true), { exitCode: 0, output: "" });
    const v = await propTestGateRun(dir, NOW, runner);
    expect(v.status).toBe("block");
    expect(v.findings[0]!.ruleId).toBe("vacuous-property-test");
    expect(ran).toBe(false); // a green run must not mask the neutering
  });

  test("suite exit 0 → pass", async () => {
    const dir = workspace();
    writeApp(dir, "export const clamp=(x:number,lo:number,hi:number)=>Math.min(hi,Math.max(lo,x));");
    const runner: PropRunner = () => ({ exitCode: 0, output: "1 pass" });
    expect((await propTestGateRun(dir, NOW, runner)).status).toBe("pass");
  });

  test("suite failure attributes the finding to the failing file's requirement", async () => {
    const dir = workspace();
    writeApp(dir, "export const clamp=(x:number)=>x;");
    const runner: PropRunner = () => ({
      exitCode: 1,
      output: `${PROPTEST_DIR}/f1.test.ts:\n(fail) F1: clamp output is always within [lo, hi]\nProperty failed after 1 tests\n{ seed: 42 }\nCounterexample: [11, 0]`,
    });
    const v = await propTestGateRun(dir, NOW, runner);
    expect(v.status).toBe("block");
    expect(v.findings).toHaveLength(1);
    expect(v.findings[0]!.ruleId).toBe("property-violated");
    expect(v.findings[0]!.file).toContain("f1.test.ts");
    expect(v.findings[0]!.message).toContain("requirement F1");
    expect(v.findings[0]!.message).toContain("Counterexample");
  });

  test("an unattributable failure still blocks (aggregate finding — fail closed)", async () => {
    const dir = workspace();
    writeApp(dir, "export const clamp=(x:number)=>x;");
    const runner: PropRunner = () => ({ exitCode: 1, output: "something exploded before any section header" });
    const v = await propTestGateRun(dir, NOW, runner);
    expect(v.status).toBe("block");
    expect(v.findings[0]!.ruleId).toBe("property-violated");
  });

  test("Law 2: production rigor BLOCKS when 0 property test files found (fail-closed)", async () => {
    const dir = workspace();
    mkdirSync(join(dir, ".vibehard"), { recursive: true });
    writeFileSync(
      join(dir, ".vibehard", "spec.json"),
      JSON.stringify({
        name: "test-app",
        realUsers: true,
      }),
    );
    const v = await propTestGateRun(dir, NOW);
    expect(v.status).toBe("block");
    expect(v.findings[0]!.ruleId).toBe("missing-mandatory-property-tests");
    expect(v.findings[0]!.severity).toBe("high");
  });

  test("Law 2: property test without numRuns: 1000 yields insufficient-fuzz-iterations", async () => {
    const dir = workspace();
    writeApp(
      dir,
      "export const clamp=(x:number,lo:number,hi:number)=>Math.min(hi,Math.max(lo,x));",
      `// @requirement F1
import { test } from "bun:test";
import fc from "fast-check";
test("F1", () => {
  fc.assert(fc.property(fc.integer(), (x) => x === x), { seed: 42, numRuns: 100 });
});
`,
    );
    const v = await propTestGateRun(dir, NOW);
    expect(v.status).toBe("block");
    expect(v.findings.some((f) => f.ruleId === "insufficient-fuzz-iterations")).toBe(true);
  });
});

describe("proptest gate — REAL bun test run (integration)", () => {
  test("a correct app passes; a broken app blocks with the requirement named", async () => {
    const good = workspace();
    writeApp(good, "export const clamp=(x:number,lo:number,hi:number)=>Math.min(hi,Math.max(lo,x));");
    const passV = await propTestGateRun(good, NOW);
    expect(passV.status).toBe("pass");

    const bad = workspace();
    // The regression the ratchet exists to catch: a "fix" that breaks the acceptance criterion.
    writeApp(bad, "export const clamp=(x:number,_lo:number,_hi:number)=>x;");
    const blockV = await propTestGateRun(bad, NOW);
    expect(blockV.status).toBe("block");
    expect(blockV.findings[0]!.ruleId).toBe("property-violated");
    expect(blockV.findings[0]!.message).toContain("requirement F1");
  }, 60_000);
});

describe("listPropTestFiles", () => {
  test("lists only *.test.ts, sorted, empty when absent", () => {
    const dir = workspace();
    expect(listPropTestFiles(dir)).toEqual([]);
    mkdirSync(join(dir, PROPTEST_DIR), { recursive: true });
    writeFileSync(join(dir, PROPTEST_DIR, "b.test.ts"), "x");
    writeFileSync(join(dir, PROPTEST_DIR, "a.test.ts"), "x");
    writeFileSync(join(dir, PROPTEST_DIR, "notes.md"), "x");
    expect(listPropTestFiles(dir)).toEqual(["a.test.ts", "b.test.ts"]);
  });
});
