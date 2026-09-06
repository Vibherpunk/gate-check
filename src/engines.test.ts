import { describe, expect, test } from "bun:test";
import {
  collectNodeDecls,
  normalizeNode,
  parseNodeDrift,
  runEngines,
} from "./engines.ts";
import { mkdtempSync as mkd, writeFileSync as wf, mkdirSync as md, rmSync as rmf } from "node:fs";
import { tmpdir as td } from "node:os";
import { join as pj } from "node:path";

describe("normalizeNode (pure)", () => {
  test("strips a leading v and zero-pads the patch to 2 digits", () => {
    expect(normalizeNode("20")).toBe("20.0.00");
    expect(normalizeNode("v20")).toBe("20.0.00");
    expect(normalizeNode("20.11")).toBe("20.11.00");
    expect(normalizeNode("20.11.5")).toBe("20.11.05");
    expect(normalizeNode("v20.11.5")).toBe("20.11.05");
    expect(normalizeNode("20.11.50")).toBe("20.11.50");
  });

  test("non-numeric / range strings normalize to null", () => {
    expect(normalizeNode(">=18.0.0")).toBeNull();
    expect(normalizeNode("^18")).toBeNull();
    expect(normalizeNode("latest")).toBeNull();
    expect(normalizeNode("")).toBeNull();
  });
});

describe("parseNodeDrift (pure)", () => {
  const ts = "2026-06-20T00:00:00.000Z";

  test("all agree → no findings (pass)", () => {
    const decls = [
      { file: "package.json", raw: "20.11.5", norm: "20.11.05" },
      { file: "Dockerfile", raw: "20.11.5", norm: "20.11.05" },
      { file: "fly.toml", raw: "20.11.5", norm: "20.11.05" },
    ];
    expect(parseNodeDrift(decls)).toEqual([]);
  });

  test("all absent → nothing to check (pass)", () => {
    expect(parseNodeDrift([])).toEqual([]);
  });

  test("drift → one high finding per offending file, naming expected value", () => {
    const decls = [
      { file: "package.json", raw: "20.11.5", norm: "20.11.05" },
      { file: "Dockerfile", raw: "18.0.0", norm: "18.0.00" },
      { file: "fly.toml", raw: "20.11.5", norm: "20.11.05" },
    ];
    const f = parseNodeDrift(decls);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ tool: "engines", ruleId: "node-version-drift", severity: "high" });
    expect(f[0]!.file).toBe("Dockerfile");
    expect(f[0]!.message).toContain("18.0");
    expect(f[0]!.message).toContain("20.11.5");
    expect(parseNodeDrift(decls).length).toBe(1);
  });

  test("missing canonical location while others declare → names the missing file", () => {
    const decls = [
      { file: "package.json", raw: "20.11.5", norm: "20.11.05" },
      { file: "Dockerfile", raw: "20.11.5", norm: "20.11.05" },
    ];
    const f = parseNodeDrift(decls);
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("missing-node-version");
    expect(f[0]!.file).toBe("fly.toml");
    expect(f[0]!.severity).toBe("high");
    expect(parseNodeDrift(decls).length).toBe(1);
  });

  test("missing multiple canonical locations names each", () => {
    const decls = [{ file: "package.json", raw: "20.11.5", norm: "20.11.05" }];
    const f = parseNodeDrift(decls);
    const missing = f.filter((x) => x.ruleId === "missing-node-version");
    const files = missing.map((x) => x.file).sort();
    expect(files).toEqual(["Dockerfile", "fly.toml"]);
  });
});

/** Scratch-project helper – module scope so every describe block can use it. */
const proj = (files: Record<string, string>): string => {
  const d = mkd(pj(td(), "vibehard-engines-"));
  for (const [name, body] of Object.entries(files)) {
    const p = pj(d, name);
    const dir = p.slice(0, p.lastIndexOf("/"));
    if (dir) md(dir, { recursive: true });
    wf(p, body);
  }
  return d;
};

describe("engines gate (I/O, fixtures)", () => {

  test("all three agree → PASS, 0 blocking", async () => {
    const d = proj({
      "package.json": JSON.stringify({ engines: { node: "20.11.5" } }),
      "Dockerfile": "FROM node:20.11.5\nRUN npm i\nCMD [\"node\",\"x\"]",
      "fly.toml": 'app = "x"\nnode_version = "20.11.5"',
    });
    const v = await runEngines(d);
    expect(v.status).toBe("pass");
    expect(v.blocking).toBe(0);
    rmf(d, { recursive: true, force: true });
  });

  test("package.json vs Dockerfile drift → BLOCK, names the Dockerfile", async () => {
    const d = proj({
      "package.json": JSON.stringify({ engines: { node: "20.11.5" } }),
      "Dockerfile": "FROM node:18\nRUN npm i\nCMD [\"node\",\"x\"]",
    });
    const v = await runEngines(d);
    expect(v.status).toBe("block");
    expect(v.blocking).toBeGreaterThan(0);
    expect(v.findings.some((f) => f.ruleId === "node-version-drift" && f.file === "Dockerfile")).toBe(true);
    expect(v.findings.some((f) => f.ruleId === "scan-failed")).toBe(false); // actually read the files
    rmf(d, { recursive: true, force: true });
  });

  test("all four absent → PASS (nothing to check)", async () => {
    const d = proj({ "package.json": JSON.stringify({ name: "x" }), "Dockerfile": "FROM debian\nCMD [\"x\"]" });
    const v = await runEngines(d);
    expect(v.status).toBe("pass");
    expect(v.blocking).toBe(0);
    rmf(d, { recursive: true, force: true });
  });

  test("a missing canonical location while others declare → BLOCK", async () => {
    const d = proj({
      "package.json": JSON.stringify({ engines: { node: "20.11.5" } }),
      "Dockerfile": "FROM node:20.11.5\nCMD [\"node\",\"x\"]",
    });
    const v = await runEngines(d);
    expect(v.status).toBe("block");
    expect(v.findings.some((f) => f.ruleId === "missing-node-version" && f.file === "fly.toml")).toBe(true);
    rmf(d, { recursive: true, force: true });
  });

  test("a web/ runtime pin must also agree with package.json", async () => {
    const d = proj({
      "package.json": JSON.stringify({ engines: { node: "20.11.5" } }),
      "web/Dockerfile": "FROM node:20.11.5\nCMD [\"node\",\"x\"]",
    });
    const agree = await runEngines(d);
    expect(agree.status).toBe("pass");
    rmf(d, { recursive: true, force: true });

    const d2 = proj({
      "package.json": JSON.stringify({ engines: { node: "20.11.5" } }),
      "web/Dockerfile": "FROM node:18\nCMD [\"node\",\"x\"]",
    });
    const drift = await runEngines(d2);
    expect(drift.status).toBe("block");
    expect(drift.findings.some((f) => f.ruleId === "node-version-drift" && f.file === "web/Dockerfile")).toBe(true);
    rmf(d2, { recursive: true, force: true });
  });
});

describe("collectNodeDecls (pure, fixture-shaped)", () => {
  test("reads package.json + Dockerfile + fly.toml", () => {
    const d = proj({
      "package.json": JSON.stringify({ engines: { node: "20.11.5" } }),
      "Dockerfile": "FROM node:20.11.5\nCMD [\"node\",\"x\"]",
      "fly.toml": 'node_version = "20.11.5"',
    });
    const decls = collectNodeDecls(d);
    expect(decls.map((x) => x.file).sort()).toEqual(["Dockerfile", "fly.toml", "package.json"]);
    rmf(d, { recursive: true, force: true });
  });
});

describe("engines gate (checked-in fixtures)", () => {
  const FIXTURES = pj(import.meta.dir, "..", "fixtures");

  test("fixtures/remediated-engines → PASS (all declarations agree)", async () => {
    const v = await runEngines(pj(FIXTURES, "remediated-engines"));
    expect(v.status).toBe("pass");
    expect(v.blocking).toBe(0);
  });

  test("fixtures/vulnerable-engines → BLOCK (package.json ↔ Dockerfile drift)", async () => {
    const v = await runEngines(pj(FIXTURES, "vulnerable-engines"));
    expect(v.status).toBe("block");
    expect(v.blocking).toBeGreaterThan(0);
    expect(v.findings.some((f) => f.ruleId === "node-version-drift" && f.file === "Dockerfile")).toBe(true);
  });
});
