import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classificationMismatch, detectSensitiveSignals, inferredClasses } from "./sensitive-signals.ts";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function proj(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "sig-"));
  dirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  return dir;
}

describe("detectSensitiveSignals — the D-1 falsifier", () => {
  test("a migration with an ssn column → pii signal with file:line evidence", () => {
    const d = proj({ "supabase/migrations/001.sql": "create table clients (\n  id uuid,\n  ssn text\n);" });
    const sigs = detectSensitiveSignals(d);
    expect(sigs.length).toBe(1);
    expect(sigs[0]!.class).toBe("pii");
    expect(sigs[0]!.evidence).toContain("001.sql:3");
  });

  test("each class is detected from its own shape: phi, financial, credentials", () => {
    const d = proj({
      "supabase/migrations/001.sql": "create table records (diagnosis text, credit_card text);",
      "src/auth.ts": "interface Row { refresh_token: string }",
    });
    expect(inferredClasses(detectSensitiveSignals(d)).sort()).toEqual(["credentials", "financial", "phi"]);
  });

  test("camelCase and kebab variants match (dateOfBirth, medical-record)", () => {
    const d = proj({ "src/types.ts": "interface P { dateOfBirth: string }\n// x\nconst k = 'medical-record';" });
    const classes = inferredClasses(detectSensitiveSignals(d));
    expect(classes).toContain("pii");
    expect(classes).toContain("phi");
  });

  test("common-in-every-app identifiers are NOT signals: email, phone, name, password (bare)", () => {
    const d = proj({
      "src/app.ts": "const user = { email: '', phone: '', full_name_display: '', password: hash(pw) };",
      "supabase/migrations/001.sql": "create table users (email text, phone text);",
    });
    expect(detectSensitiveSignals(d)).toEqual([]);
  });

  test("comment lines are ignored (a TODO about SSNs is not a data model)", () => {
    const d = proj({ "src/app.ts": "// TODO: maybe support ssn later\n-- ssn note\nconst x = 1;" });
    expect(detectSensitiveSignals(d)).toEqual([]);
  });

  test("word boundaries hold: 'adobe' does not contain a dob signal", () => {
    const d = proj({ "src/app.ts": "import adobe from 'adobe'; const cardNumberless = false;" });
    // `cardNumberless` — trailing lookahead rejects the run-on identifier
    expect(detectSensitiveSignals(d)).toEqual([]);
  });

  test("one evidence entry per class+file (a 40-column schema doesn't produce 40 findings)", () => {
    const d = proj({ "supabase/migrations/001.sql": "ssn text, passport_number text, tax_id text" });
    const sigs = detectSensitiveSignals(d);
    expect(sigs.filter((s) => s.class === "pii").length).toBe(1);
  });

  test("clean project → empty (a genuinely non-sensitive app keeps its fast N/A)", () => {
    const d = proj({ "src/app.ts": "export const todo = ['buy milk'];", "supabase/migrations/001.sql": "create table todos (id uuid, title text, done boolean);" });
    expect(detectSensitiveSignals(d)).toEqual([]);
  });
});

describe("classificationMismatch", () => {
  test("high severity, names the classes and the evidence, offers both resolutions", () => {
    const f = classificationMismatch("compliance", [{ class: "pii", evidence: "m.sql:3 — `ssn`" }]);
    expect(f.severity).toBe("high");
    expect(f.ruleId).toBe("classification-mismatch");
    expect(f.message).toContain("pii");
    expect(f.message).toContain("m.sql:3");
    expect(f.message).toContain("correct the classification");
    expect(f.message).toContain("remove the sensitive fields");
  });
});
