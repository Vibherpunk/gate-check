import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runMigrate, extensionsIn } from "./migrate.ts";

const tmps: string[] = [];
afterEach(() => {
  for (const d of tmps.splice(0)) rmSync(d, { recursive: true, force: true });
});
function ws(migrations?: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "vibehard-migrate-"));
  tmps.push(d);
  if (migrations) {
    mkdirSync(join(d, "supabase", "migrations"), { recursive: true });
    for (const [name, sql] of Object.entries(migrations)) writeFileSync(join(d, "supabase", "migrations", name), sql);
  }
  return d;
}

describe("migrate gate — executes migrations against a real (embedded) Postgres", () => {
  test("BLOCKS an invalid 'FOR INSERT UPDATE DELETE' policy (the bug that shipped to ProCare)", async () => {
    const v = await runMigrate(
      ws({
        "001_init.sql": `CREATE TABLE "t" (id uuid primary key);
ALTER TABLE "t" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "p" ON "t" FOR INSERT UPDATE DELETE USING (true);`,
      }),
    );
    expect(v.status).toBe("block");
    expect(v.findings[0]!.ruleId).toBe("migration-failed");
    expect(v.findings[0]!.file).toContain("001_init.sql");
  });

  test("BLOCKS a forward foreign-key (table referenced before it's created)", async () => {
    const v = await runMigrate(
      ws({ "001.sql": `CREATE TABLE "a" (id uuid primary key, b_id uuid references "b"(id));
CREATE TABLE "b" (id uuid primary key);` }),
    );
    expect(v.status).toBe("block");
    expect(v.findings[0]!.message).toMatch(/does NOT apply/i);
  });

  test("BLOCKS a function that references a table created later (execution-order bug)", async () => {
    const v = await runMigrate(
      ws({ "001.sql": `CREATE FUNCTION centerid() RETURNS uuid LANGUAGE sql AS $$ SELECT "centerId" FROM "Staff" LIMIT 1 $$;
CREATE TABLE "Staff" (id uuid primary key, "centerId" uuid);` }),
    );
    expect(v.status).toBe("block");
  });

  test("PASSES a valid, correctly-ordered schema (incl. Supabase auth.uid + uuid stubs)", async () => {
    const v = await runMigrate(
      ws({
        "001.sql": `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE "Center" (id uuid primary key default uuid_generate_v4());
CREATE TABLE "Staff" (id uuid primary key, "authUserId" uuid references auth.users(id), "centerId" uuid references "Center"(id));
ALTER TABLE "Staff" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own" ON "Staff" FOR ALL USING ("authUserId" = auth.uid());`,
      }),
    );
    expect(v.status).toBe("pass");
    // The only finding is the non-blocking extension advisory (audit2 D — uuid-ossp is shimmed + surfaced).
    expect(v.findings.filter((f) => f.severity === "high" || f.severity === "critical")).toHaveLength(0);
    expect(v.findings.every((f) => f.ruleId === "extension-shimmed")).toBe(true);
  });

  test("applies multiple migrations IN ORDER (later file depends on earlier)", async () => {
    const v = await runMigrate(
      ws({
        "001_tables.sql": `CREATE TABLE "x" (id uuid primary key);`,
        "002_alter.sql": `ALTER TABLE "x" ADD COLUMN note text;`,
      }),
    );
    expect(v.status).toBe("pass");
  });

  test("no supabase/migrations dir → N/A (no block)", async () => {
    expect((await runMigrate(ws())).status).toBe("pass");
  });

  test("injected applier failure surfaces as a localized blocking finding (no pglite needed)", async () => {
    const v = await runMigrate(ws({ "001.sql": "SELECT 1;" }), {
      apply: async () => ({ file: "supabase/migrations/001.sql", error: "boom" }),
    });
    expect(v.status).toBe("block");
    expect(v.findings[0]!.message).toContain("boom");
  });

  test("audit2 D: extensionsIn lists every CREATE EXTENSION name", () => {
    const names = extensionsIn([
      { file: "a.sql", sql: `create extension if not exists "pgcrypto";\ncreate extension citext;` },
      { file: "b.sql", sql: `CREATE EXTENSION vector;` },
    ]);
    expect(names).toEqual(["citext", "pgcrypto", "vector"]);
  });

  test("audit2 D: a shimmed extension is SURFACED as a non-blocking advisory (not silently dropped)", async () => {
    const v = await runMigrate(ws({ "001.sql": `create extension if not exists pg_trgm;\ncreate table "t" (id uuid primary key);` }), {
      apply: async () => null, // applies clean
    });
    expect(v.status).toBe("pass"); // advisory is medium → does not block
    const ext = v.findings.find((f) => f.ruleId === "extension-shimmed");
    expect(ext?.severity).toBe("medium");
    expect(ext?.message).toMatch(/pg_trgm/);
  });
});
