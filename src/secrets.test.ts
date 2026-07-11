import { describe, expect, test } from "bun:test";
import { interpretGitleaks, parseGitleaks } from "./secrets.ts";
import { verdictOf } from "./types.ts";

describe("parseGitleaks (pure)", () => {
  test("maps gitleaks JSON into structured Finding[]", () => {
    const raw = [
      { RuleID: "stripe-access-token", Description: "Found a Stripe Access Token", File: "/src/server.js", StartLine: 10 },
      { RuleID: "private-key", Description: "Private key", File: "/src/cert/server.key", StartLine: 1 },
    ];
    const f = parseGitleaks(raw);
    expect(f).toHaveLength(2);
    expect(f[0]).toMatchObject({
      tool: "gitleaks",
      ruleId: "stripe-access-token",
      severity: "high",
      file: "/src/server.js",
      line: 10,
    });
  });

  test("empty / malformed input yields no findings", () => {
    expect(parseGitleaks([])).toEqual([]);
    expect(parseGitleaks(null)).toEqual([]);
    expect(parseGitleaks({})).toEqual([]);
  });
});

describe("secrets are always blocking", () => {
  test("any leaked secret forces a block", () => {
    const findings = parseGitleaks([{ RuleID: "stripe-access-token", File: "p", StartLine: 1 }]);
    expect(verdictOf("secrets", findings, "2026-06-20T00:00:00.000Z").status).toBe("block");
  });
});

describe("interpretGitleaks — fail CLOSED on a scan that didn't run", () => {
  test("exit 0 clean (empty or [] output) → no findings", () => {
    expect(interpretGitleaks("[]", 0, "", "/proj")).toEqual([]);
    expect(interpretGitleaks("", 0, "", "/proj")).toEqual([]);
  });

  test("exit 1 with leaks → findings", () => {
    const out = JSON.stringify([{ RuleID: "stripe", File: "p", StartLine: 1 }]);
    expect(interpretGitleaks(out, 1, "", "/proj")).toHaveLength(1);
  });

  test("exit >1 (scanner error) → CRITICAL scan-failed, which blocks", () => {
    const f = interpretGitleaks("", 2, "boom", "/proj");
    expect(f[0]).toMatchObject({ tool: "gitleaks", ruleId: "scan-failed", severity: "critical" });
  });

  test("non-array output → scan-failed", () => {
    expect(interpretGitleaks("{}", 0, "", "/proj")[0]?.ruleId).toBe("scan-failed");
  });
});
