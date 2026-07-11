import { describe, expect, test } from "bun:test";
import { interpretTrivy, mapTrivySeverity, parseTrivy } from "./depvuln.ts";
import { verdictOf } from "./types.ts";

// Shaped like real `trivy fs --format json --scanners vuln` output.
const TRIVY_JSON = {
  SchemaVersion: 2,
  Results: [
    {
      Target: "package-lock.json",
      Class: "lang-pkgs",
      Type: "npm",
      Vulnerabilities: [
        {
          VulnerabilityID: "CVE-2019-10744",
          PkgName: "lodash",
          InstalledVersion: "4.17.4",
          FixedVersion: "4.17.12",
          Severity: "CRITICAL",
          Title: "prototype pollution in defaultsDeep",
        },
        {
          VulnerabilityID: "CVE-2018-16487",
          PkgName: "lodash",
          InstalledVersion: "4.17.4",
          FixedVersion: "4.17.11",
          Severity: "MEDIUM",
          Title: "prototype pollution",
        },
      ],
    },
  ],
};

describe("mapTrivySeverity", () => {
  test("CRITICAL/HIGH/MEDIUM/LOW → our scale; unknown → low", () => {
    expect(mapTrivySeverity("CRITICAL")).toBe("critical");
    expect(mapTrivySeverity("HIGH")).toBe("high");
    expect(mapTrivySeverity("MEDIUM")).toBe("medium");
    expect(mapTrivySeverity("LOW")).toBe("low");
    expect(mapTrivySeverity("UNKNOWN")).toBe("low");
    expect(mapTrivySeverity(undefined)).toBe("low");
  });
});

describe("parseTrivy (pure)", () => {
  test("maps trivy vulns into structured Finding[]", () => {
    const f = parseTrivy(TRIVY_JSON);
    expect(f).toHaveLength(2);
    expect(f[0]).toMatchObject({
      tool: "trivy",
      ruleId: "CVE-2019-10744",
      severity: "critical",
      file: "package-lock.json",
    });
    expect(f[0]!.message).toContain("lodash@4.17.4");
    expect(f[0]!.message).toContain("fixed in 4.17.12");
    expect(f[1]?.severity).toBe("medium");
  });

  test("no-fix vulnerability is labeled", () => {
    const f = parseTrivy({ Results: [{ Target: "go.mod", Vulnerabilities: [{ VulnerabilityID: "CVE-x", PkgName: "p", InstalledVersion: "1", Severity: "HIGH" }] }] });
    expect(f[0]!.message).toContain("no fix available yet");
  });

  test("empty / no-deps / malformed input yields no findings", () => {
    expect(parseTrivy({ Results: [] })).toEqual([]);
    expect(parseTrivy({ Results: null })).toEqual([]);
    expect(parseTrivy({})).toEqual([]);
    expect(parseTrivy(null)).toEqual([]);
  });
});

describe("interpretTrivy (fail-closed, §11)", () => {
  test("a clean scan (exit 0, valid JSON, no deps) PASSES — not scan-failed", () => {
    // The key no-false-fail case: trivy emits Results:null for a no-dependency project.
    expect(interpretTrivy(JSON.stringify({ SchemaVersion: 2, Results: null }), 0, "", "/src")).toEqual([]);
    expect(interpretTrivy(JSON.stringify({ SchemaVersion: 2 }), 0, "", "/src")).toEqual([]);
  });

  test("a successful scan with vulns yields the findings", () => {
    const f = interpretTrivy(JSON.stringify(TRIVY_JSON), 0, "", "/src");
    expect(f).toHaveLength(2);
    expect(f[0]!.ruleId).toBe("CVE-2019-10744");
  });

  test("a non-zero exit fails CLOSED → CRITICAL scan-failed (blocks)", () => {
    const f = interpretTrivy("", 1, "trivy: DB download failed", "/src");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ tool: "trivy", ruleId: "scan-failed", severity: "critical", file: "/src" });
    expect(verdictOf("depvuln", f, "2026-06-21T00:00:00.000Z").status).toBe("block");
  });

  test("exit 0 but unparseable output fails CLOSED (scanner didn't really run)", () => {
    expect(interpretTrivy("not json", 0, "", "/src")[0]).toMatchObject({ ruleId: "scan-failed", severity: "critical" });
    expect(interpretTrivy("", 0, "", "/src")[0]).toMatchObject({ ruleId: "scan-failed" });
  });
});

describe("depvuln disposition", () => {
  const ts = "2026-06-21T00:00:00.000Z";
  test("a critical/high dep vuln blocks; only medium/low passes", () => {
    expect(verdictOf("depvuln", parseTrivy(TRIVY_JSON), ts).status).toBe("block"); // has a CRITICAL
    expect(verdictOf("depvuln", parseTrivy(TRIVY_JSON), ts).blocking).toBe(1); // the critical; medium not blocking

    const mediumOnly = parseTrivy({ Results: [{ Target: "x", Vulnerabilities: [{ VulnerabilityID: "CVE-m", Severity: "MEDIUM", PkgName: "p", InstalledVersion: "1" }] }] });
    expect(verdictOf("depvuln", mediumOnly, ts).status).toBe("pass");
  });
});

import { scanGapFindings } from "./depvuln.ts";
import { mkdtempSync as mkd, writeFileSync as wf, mkdirSync as md, rmSync as rmf } from "node:fs";
import { tmpdir as td } from "node:os";
import { join as pj } from "node:path";
describe("depvuln — a no-lockfile scan is flagged incomplete, not a silent pass", () => {
  const proj = (pkg: object, lock = false) => {
    const d = mkd(pj(td(), "vibehard-depgap-"));
    wf(pj(d, "package.json"), JSON.stringify(pkg));
    if (lock) wf(pj(d, "package-lock.json"), "{}");
    return d;
  };
  test("deps declared but no lockfile → a medium advisory finding", () => {
    const d = proj({ dependencies: { next: "^15", react: "^18" } });
    const f = scanGapFindings(d);
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("depscan-incomplete");
    expect(f[0]!.severity).toBe("medium"); // visible, non-blocking
    rmf(d, { recursive: true, force: true });
  });
  test("a lockfile present → no advisory (the scan was complete)", () => {
    const d = proj({ dependencies: { next: "^15" } }, true);
    expect(scanGapFindings(d)).toHaveLength(0);
    rmf(d, { recursive: true, force: true });
  });
  test("no deps declared → no advisory", () => {
    const d = proj({});
    expect(scanGapFindings(d)).toHaveLength(0);
    rmf(d, { recursive: true, force: true });
  });
});
