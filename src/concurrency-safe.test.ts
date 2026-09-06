import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkConcurrencySafe, concurrencySafeGate } from "./concurrency-safe.ts";

const tmps: string[] = [];
afterEach(() => {
  for (const d of tmps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function ws(files: Record<string, string> = {}): string {
  const d = mkdtempSync(join(tmpdir(), "gate-concurrency-safe-"));
  tmps.push(d);
  for (const [rel, content] of Object.entries(files)) {
    const full = join(d, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return d;
}

describe("concurrency-safe gate (Law 3)", () => {
  test("clean project with OCC versioning and idempotency keys passes", async () => {
    const dir = ws({
      "supabase/migrations/001_orders.sql": `
        CREATE TABLE orders (
          id UUID PRIMARY KEY,
          total NUMERIC,
          version INT NOT NULL DEFAULT 1
        );
      `,
      "src/api/orders/route.ts": `
        export async function POST(req: Request) {
          const key = req.headers.get("Idempotency-Key");
          return new Response("ok");
        }
      `,
    });
    const findings = checkConcurrencySafe(dir);
    expect(findings).toHaveLength(0);
    const v = await concurrencySafeGate.run(dir);
    expect(v.status).toBe("pass");
  });

  test("flags state-bearing table missing OCC version column", async () => {
    const dir = ws({
      "supabase/migrations/001_invoices.sql": `
        CREATE TABLE customer_invoices (
          id UUID PRIMARY KEY,
          amount INT
        );
      `,
    });
    const findings = checkConcurrencySafe(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("missing-occ-versioning");
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.message).toContain("customer_invoices");
    const v = await concurrencySafeGate.run(dir);
    expect(v.status).toBe("block");
  });

  test("ignores non-state-bearing tables without version column", async () => {
    const dir = ws({
      "supabase/migrations/001_tags.sql": `
        CREATE TABLE tags (
          id UUID PRIMARY KEY,
          name TEXT
        );
      `,
    });
    const findings = checkConcurrencySafe(dir);
    expect(findings).toHaveLength(0);
  });

  test("flags POST route missing idempotency key check", async () => {
    const dir = ws({
      "src/api/checkout/route.ts": `
        export async function POST(req: Request) {
          return new Response("charged");
        }
      `,
    });
    const findings = checkConcurrencySafe(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("missing-idempotency-key");
    expect(findings[0]!.severity).toBe("medium");
  });
});
