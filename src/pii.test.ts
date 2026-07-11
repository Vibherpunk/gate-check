import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPii, scanPii } from "./pii.ts";

const ids = (code: string): string[] => scanPii([{ rel: "app.ts", code }]).map((f) => f.ruleId);

describe("scanPii — flags real PII leaks", () => {
  test("PII written to logs via property access or interpolation", () => {
    expect(ids("console.log(user.email)")).toContain("pii-in-logs");
    expect(ids("logger.info(`reset link for ${user.ssn}`)")).toContain("pii-in-logs");
    expect(ids("console.error('save failed', patient.diagnosis)")).toContain("pii-in-logs");
    expect(ids('print(f"sending to {customer.phone}")')).toContain("pii-in-logs");
  });
  test("PII read from a URL / query string", () => {
    expect(ids("const e = req.query.email;")).toContain("pii-in-url");
    expect(ids('const s = url.searchParams.get("ssn");')).toContain("pii-in-url");
    expect(ids('phone = request.args.get("phone")')).toContain("pii-in-url");
  });
  test("every finding is high severity (→ blocking)", () => {
    expect(scanPii([{ rel: "a.ts", code: "console.log(user.email)" }]).every((f) => f.severity === "high")).toBe(true);
  });
});

describe("scanPii — precision (does NOT flag labels / non-PII)", () => {
  test("quoted labels and non-PII logs are ignored", () => {
    expect(ids('console.log("email sent to the user")')).toEqual([]);
    expect(ids('console.log("password reset requested")')).toEqual([]);
    expect(ids("console.log(order.total, items.length)")).toEqual([]);
    expect(ids("const emailSent = true; // not logged")).toEqual([]);
    expect(ids("// remember to email the user")).toEqual([]);
  });
});

describe("scanPii — F6 (audit2): bracket access can't bypass detection", () => {
  test("bracket access to a PII field in a log is flagged", () => {
    expect(ids(`console.log(user["email"])`)).toContain("pii-in-logs");
    expect(ids(`logger.info(row['ssn'])`)).toContain("pii-in-logs");
  });

  test("bracket access from req.query is flagged", () => {
    expect(ids(`const e = req.query["email"];`)).toContain("pii-in-url");
  });

  test("bracket access to a NON-PII field is still ignored (precision held)", () => {
    expect(ids(`console.log(obj["status"])`)).toEqual([]);
  });
});

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function appDir(sensitive: boolean, code: string): string {
  const dir = mkdtempSync(join(tmpdir(), "pii-gate-"));
  dirs.push(dir);
  mkdirSync(join(dir, ".vibehard"), { recursive: true });
  writeFileSync(join(dir, ".vibehard", "spec.json"), JSON.stringify({ name: "x", sensitiveData: sensitive ? ["pii"] : ["none"], dataEntities: [] }));
  writeFileSync(join(dir, "app.ts"), code);
  return dir;
}

describe("runPii — classification-driven", () => {
  test("a SENSITIVE app that logs PII → BLOCK", async () => {
    const v = await runPii(appDir(true, "console.log(user.email)"), "t");
    expect(v.status).toBe("block");
    expect(v.blocking).toBeGreaterThan(0);
  });
  test("a NON-sensitive app → N/A (nothing to check; not a vacuous pass)", async () => {
    const v = await runPii(appDir(false, "console.log(user.email)"), "t");
    expect(v.status).toBe("n/a");
    expect(v.blocking).toBe(0); // n/a never blocks a deploy
  });
  test("a sensitive app with no PII leak → PASS", async () => {
    const v = await runPii(appDir(true, "console.log('app started'); const id = req.query.id;"), "t");
    expect(v.status).toBe("pass");
  });
});

describe("runPii — D-1 (SECURITY_AUDIT_4): a 'none' declaration is falsifiable", () => {
  test("spec says 'none' but the code stores diagnoses → gate RUNS: mismatch blocks + leaks still caught", async () => {
    const dir = appDir(false, "interface Visit { diagnosis: string }\nconsole.log(visit.diagnosis)");
    const v = await runPii(dir, "t");
    expect(v.status).toBe("block");
    const ids = v.findings.map((f) => f.ruleId);
    expect(ids).toContain("classification-mismatch"); // the false claim itself
    expect(ids).toContain("pii-in-logs"); // and the leak scan ran anyway
  });

  test("spec says 'none' and the code corroborates it → N/A preserved (email alone is not a signal)", async () => {
    const v = await runPii(appDir(false, "console.log(user.email)"), "t");
    expect(v.status).toBe("n/a");
  });
});
