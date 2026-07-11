import { describe, expect, test } from "bun:test";
import { interpretSemgrep, mapSeverity, parseSemgrep } from "./sast.ts";
import { verdictOf } from "./types.ts";

describe("mapSeverity", () => {
  test("ERROR→high, WARNING→medium, else low", () => {
    expect(mapSeverity("ERROR")).toBe("high");
    expect(mapSeverity("WARNING")).toBe("medium");
    expect(mapSeverity(undefined)).toBe("low");
    expect(mapSeverity("INFO")).toBe("low");
  });
});

describe("parseSemgrep (pure)", () => {
  test("maps semgrep JSON into structured Finding[]", () => {
    const raw = {
      results: [
        {
          check_id: "rules.sqlite-template-literal-query",
          path: "/src/server.js",
          start: { line: 30 },
          extra: { severity: "ERROR", message: "SQL injection" },
        },
        {
          check_id: "x.audit.xss",
          path: "/src/v.ejs",
          start: { line: 5 },
          extra: { severity: "WARNING", message: "xss" },
        },
      ],
    };
    const f = parseSemgrep(raw);
    expect(f).toHaveLength(2);
    expect(f[0]).toMatchObject({
      tool: "semgrep",
      ruleId: "rules.sqlite-template-literal-query",
      severity: "high",
      file: "/src/server.js",
      line: 30,
    });
    expect(f[1]?.severity).toBe("medium");
  });

  test("empty / malformed input yields no findings", () => {
    expect(parseSemgrep({})).toEqual([]);
    expect(parseSemgrep(null)).toEqual([]);
    expect(parseSemgrep({ results: [] })).toEqual([]);
  });
});

describe("verdictOf (deterministic disposition)", () => {
  const ts = "2026-06-20T00:00:00.000Z";
  test("a high finding forces block; only-low passes", () => {
    const high = parseSemgrep({ results: [{ check_id: "a", path: "p", start: { line: 1 }, extra: { severity: "ERROR" } }] });
    expect(verdictOf("sast", high, ts).status).toBe("block");
    expect(verdictOf("sast", high, ts).blocking).toBe(1);

    const low = parseSemgrep({ results: [{ check_id: "b", path: "p", start: { line: 1 }, extra: { severity: "INFO" } }] });
    expect(verdictOf("sast", low, ts).status).toBe("pass");
    expect(verdictOf("sast", low, ts).blocking).toBe(0);
  });
});

describe("interpretSemgrep — fail CLOSED on a scan that didn't run", () => {
  test("valid semgrep JSON → parsed findings", () => {
    const out = JSON.stringify({
      results: [{ check_id: "a", path: "p", start: { line: 1 }, extra: { severity: "ERROR" } }],
      errors: [],
    });
    const f = interpretSemgrep(out, 0, "", "/proj");
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
  });

  test("clean scan (empty results) → no findings (a true pass)", () => {
    expect(interpretSemgrep(JSON.stringify({ results: [], errors: [] }), 0, "", "/proj")).toEqual([]);
  });

  test("scanner failed (no/invalid/empty-object JSON) → CRITICAL scan-failed, which blocks", () => {
    for (const bad of ["", "not json", "{}", JSON.stringify({ nope: 1 })]) {
      const f = interpretSemgrep(bad, 2, "boom", "/proj");
      expect(f).toHaveLength(1);
      expect(f[0]).toMatchObject({ tool: "semgrep", ruleId: "scan-failed", severity: "critical" });
    }
  });

  test("audit2 C5: a config/ruleset load error → scan-failed even with a valid (empty) results array", () => {
    const out = JSON.stringify({ results: [], errors: [{ level: "error", type: "ConfigError", message: "could not load config p/default" }], paths: { scanned: ["a.ts"] } });
    const f = interpretSemgrep(out, 7, "", "/proj");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: "scan-failed", severity: "critical" });
    expect(f[0]!.message).toMatch(/ruleset\/config failed to load/i);
  });

  test("audit2 C5: zero files scanned → scan-failed (the scan didn't really run)", () => {
    const out = JSON.stringify({ results: [], errors: [], paths: { scanned: [] } });
    const f = interpretSemgrep(out, 0, "", "/proj");
    expect(f[0]).toMatchObject({ ruleId: "scan-failed", severity: "critical" });
    expect(f[0]!.message).toMatch(/scanned 0 files/i);
  });

  test("audit2 C5: a real scan (files scanned, no config error) still passes clean", () => {
    const out = JSON.stringify({ results: [], errors: [], paths: { scanned: ["a.ts", "b.ts"] } });
    expect(interpretSemgrep(out, 0, "", "/proj")).toEqual([]);
  });
});
