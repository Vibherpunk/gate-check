import { describe, expect, test } from "bun:test";
import { applyRigor, checkContainer, checkPinning, checkReadme, checkTsStrict } from "./prod-readiness.ts";
import type { Finding } from "./types.ts";

describe("checkPinning — unbounded version ranges", () => {
  test("`latest`, `*`, `x`, and `>=` are flagged; exact/^/~ are fine", () => {
    const f = checkPinning({ a: "latest", b: "*", c: "1.x", d: ">=2.0.0", e: "^1.2.3", g: "~1.2.0", h: "1.2.3" });
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("unpinned-dependency");
    expect(f[0]!.message).toMatch(/a@latest/);
    expect(f[0]!.message).toMatch(/d@>=2\.0\.0/);
    expect(f[0]!.message).not.toMatch(/e@|g@|h@/); // bounded ones not listed
  });

  test("all bounded → no finding", () => {
    expect(checkPinning({ next: "^14.2.5", react: "18.2.0", tw: "~3.4.0" })).toEqual([]);
  });
});

describe("checkReadme", () => {
  test("missing or trivial → advisory; a real one → clean", () => {
    expect(checkReadme(null)[0]!.ruleId).toBe("missing-readme");
    expect(checkReadme("hi")[0]!.severity).toBe("medium"); // too short
    expect(checkReadme("just some prose with no heading, ".repeat(20))).toHaveLength(1); // no heading
    expect(checkReadme(`# My App\n\n${"It does things. ".repeat(20)}`)).toEqual([]);
  });
});

describe("checkContainer — only when a Dockerfile is present", () => {
  test("no Dockerfile → nothing", () => {
    expect(checkContainer(null, false)).toEqual([]);
  });

  test("root user + unpinned base + no .dockerignore → three findings", () => {
    const ids = checkContainer("FROM node:20\nRUN npm i\nCMD [\"node\",\"x\"]", false).map((f) => f.ruleId);
    expect(ids).toEqual(["container-runs-as-root", "unpinned-base-image", "missing-dockerignore"]);
  });

  test("non-root USER + digest-pinned base + .dockerignore → clean", () => {
    const df = "FROM node:20@sha256:" + "a".repeat(64) + "\nUSER app\nCMD [\"node\",\"x\"]";
    expect(checkContainer(df, true)).toEqual([]);
  });
});

describe("checkTsStrict", () => {
  test("strict off → advisory; strict on → clean; no tsconfig → nothing", () => {
    expect(checkTsStrict('{"compilerOptions":{"strict":false}}')[0]!.ruleId).toBe("typescript-not-strict");
    expect(checkTsStrict('{"compilerOptions":{}}')).toHaveLength(1); // strict absent
    expect(checkTsStrict('{"compilerOptions":{"strict":true}}')).toEqual([]);
    expect(checkTsStrict(null)).toEqual([]);
  });
});

describe("applyRigor — §16 block @prod, warn @prototype", () => {
  const findings: Finding[] = [
    { tool: "prod-readiness", ruleId: "unpinned-dependency", severity: "high", file: "package.json", message: "x" },
    { tool: "prod-readiness", ruleId: "missing-readme", severity: "medium", file: "README.md", message: "y" },
  ];

  test("production → severities unchanged (the high one still blocks)", () => {
    expect(applyRigor(findings, "production").map((f) => f.severity)).toEqual(["high", "medium"]);
  });

  test("prototype → blockers downgraded to advisories (nothing blocks a throwaway)", () => {
    expect(applyRigor(findings, "prototype").map((f) => f.severity)).toEqual(["medium", "medium"]);
  });
});
