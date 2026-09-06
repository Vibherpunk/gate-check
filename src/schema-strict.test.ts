import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkSchemaStrict, schemaStrictGate } from "./schema-strict.ts";

const tmps: string[] = [];
afterEach(() => {
  for (const d of tmps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function ws(files: Record<string, string> = {}): string {
  const d = mkdtempSync(join(tmpdir(), "gate-schema-strict-"));
  tmps.push(d);
  for (const [rel, content] of Object.entries(files)) {
    const full = join(d, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return d;
}

describe("schema-strict gate (Law 1)", () => {
  test("clean project has 0 findings and passes", async () => {
    const dir = ws({
      "src/index.ts": `export function add(a: number, b: number): number { return a + b; }`,
    });
    const findings = checkSchemaStrict(dir);
    expect(findings).toHaveLength(0);
    const v = await schemaStrictGate.run(dir);
    expect(v.status).toBe("pass");
  });

  test("flags @ts-ignore and @ts-nocheck as critical", async () => {
    const dir = ws({
      "src/ignore.ts": `// @ts-ignore\nconst x = 1;`,
      "src/nocheck.ts": `// @ts-nocheck\nconst y = 2;`,
    });
    const findings = checkSchemaStrict(dir);
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.ruleId === "typescript-suppression-forbidden")).toBe(true);
    expect(findings.every((f) => f.severity === "critical")).toBe(true);
  });

  test("flags untyped any (: any, as any, <any>) as high", async () => {
    const dir = ws({
      "src/annotated.ts": `let a: any = 1;`,
      "src/cast.ts": `const b = "hello" as any;`,
      "src/generic.ts": `const c = <any>"hello";`,
    });
    const findings = checkSchemaStrict(dir);
    expect(findings).toHaveLength(3);
    expect(findings.every((f) => f.ruleId === "untyped-any-forbidden")).toBe(true);
    expect(findings.every((f) => f.severity === "high")).toBe(true);
  });

  test("flags POST/PUT/PATCH routes without Zod validation", async () => {
    const dir = ws({
      "src/api/users/route.ts": `export async function POST(req: Request) { return new Response("ok"); }`,
      "app/api/orders/route.ts": `export function PUT(req: Request) { return new Response("ok"); }`,
      "src/routes/item.ts": `export async function PATCH() { return new Response("ok"); }`,
    });
    const findings = checkSchemaStrict(dir);
    expect(findings).toHaveLength(3);
    expect(findings.every((f) => f.ruleId === "missing-runtime-schema-validation")).toBe(true);
    expect(findings.every((f) => f.severity === "high")).toBe(true);
  });

  test("passes POST route with Zod .parse or .safeParse", async () => {
    const dir = ws({
      "src/api/users/route.ts": `
        import { z } from "zod";
        const Schema = z.object({ name: z.string() });
        export async function POST(req: Request) {
          const body = Schema.parse(await req.json());
          return new Response(body.name);
        }
      `,
    });
    const findings = checkSchemaStrict(dir);
    expect(findings).toHaveLength(0);
    const v = await schemaStrictGate.run(dir);
    expect(v.status).toBe("pass");
  });
});
