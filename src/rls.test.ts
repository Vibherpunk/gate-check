import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createdTables,
  detectSupabaseUsage,
  parseRls,
  parseRlsCoverage,
  parseServiceKeyUsage,
  pkgUsesSupabase,
  readMigrations,
  rlsEnabledTables,
  runRls,
} from "./rls.ts";
import { verdictOf } from "./types.ts";

const tmps: string[] = [];
afterEach(async () => {
  for (const d of tmps.splice(0)) await rm(d, { recursive: true, force: true });
});
async function scratch(files: Record<string, string>): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "vibehard-rls-"));
  tmps.push(d);
  for (const [path, content] of Object.entries(files)) await Bun.write(join(d, path), content);
  return d;
}

const VULN = `
create table public.profiles (id uuid primary key, ssn text);

create table public.documents (id uuid primary key, owner uuid);
alter table public.documents enable row level security;
create policy "all_documents" on public.documents for select using (true);
`;

const FIXED = `
create table public.profiles (id uuid primary key, ssn text);
alter table public.profiles enable row level security;
create policy "own_profile" on public.profiles for select using (auth.uid() = id);

create table public.documents (id uuid primary key, owner uuid);
alter table public.documents enable row level security;
create policy "own_documents" on public.documents for select using (auth.uid() = owner);
`;

describe("parseRls (pure)", () => {
  test("RLS off → critical; using(true) → high (the CVE-2025-48757 pattern)", () => {
    const f = parseRls([{ file: "supabase/migrations/0001_init.sql", sql: VULN }]);
    expect(f).toHaveLength(2);

    const profiles = f.find((x) => x.message.includes("profiles"));
    expect(profiles).toMatchObject({ tool: "rls", ruleId: "rls-disabled", severity: "critical" });
    expect(profiles?.file).toBe("supabase/migrations/0001_init.sql");
    expect(profiles?.line).toBe(2); // 1-based, leading newline + create on line 2

    const documents = f.find((x) => x.message.includes("documents"));
    expect(documents).toMatchObject({ ruleId: "rls-policy-using-true", severity: "high" });
  });

  test("remediated migrations yield no findings", () => {
    expect(parseRls([{ file: "m.sql", sql: FIXED }])).toEqual([]);
  });

  test("enable can live in a different source than the create table", () => {
    const split = parseRls([
      { file: "0001_tables.sql", sql: "create table public.profiles (id uuid primary key);" },
      { file: "0002_rls.sql", sql: "alter table public.profiles enable row level security; create policy p on public.profiles for select using (auth.uid() = id);" },
    ]);
    expect(split).toEqual([]);
  });

  test("each table is reported once, attributed to where it was created", () => {
    const dup = parseRls([
      { file: "a.sql", sql: "create table public.profiles (id uuid);\ncreate table public.profiles (id uuid);" },
    ]);
    expect(dup).toHaveLength(1);
    expect(dup[0]?.line).toBe(1);
  });

  test("no migrations → no findings", () => {
    expect(parseRls([])).toEqual([]);
  });
});

describe("readMigrations (I/O)", () => {
  test("a project with no supabase/migrations dir yields [] (no DB → nothing to check)", async () => {
    // import.meta.dir has no supabase/migrations — must not throw.
    expect(await readMigrations(join(import.meta.dir, "no-such-project"))).toEqual([]);
  });

  test("reads the remediated fixture's migrations", async () => {
    const sources = await readMigrations(join(import.meta.dir, "..", "fixtures", "remediated"));
    expect(sources.length).toBeGreaterThan(0);
    expect(parseRls(sources)).toEqual([]); // remediated → clean
  });
});

describe("rls disposition", () => {
  const ts = "2026-06-20T00:00:00.000Z";
  test("an exposed table forces a block", () => {
    const f = parseRls([{ file: "m.sql", sql: VULN }]);
    const v = verdictOf("rls", f, ts);
    expect(v.status).toBe("block");
    expect(v.blocking).toBe(2);
  });
});

describe("rls-policy-authenticated (WARN — broad but not open to the world)", () => {
  const ts = "2026-06-21T00:00:00.000Z";
  const mk = (using: string) =>
    [
      "create table public.t (id uuid primary key, user_id uuid);",
      "alter table public.t enable row level security;",
      `create policy p on public.t for select using (${using});`,
    ].join("\n");

  test("`auth.uid() is not null` → one MEDIUM finding, verdict still PASS (does not block)", () => {
    const f = parseRls([{ file: "m.sql", sql: mk("auth.uid() is not null") }]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ tool: "rls", ruleId: "rls-policy-authenticated", severity: "medium" });
    expect(verdictOf("rls", f, ts).status).toBe("pass"); // medium is a warning, not a block
  });

  test("`auth.role() = 'authenticated'` → MEDIUM warn", () => {
    const f = parseRls([{ file: "m.sql", sql: mk("auth.role() = 'authenticated'") }]);
    expect(f[0]).toMatchObject({ ruleId: "rls-policy-authenticated", severity: "medium" });
  });

  test("a caller-scoped policy (`auth.uid() = user_id`) → no warning", () => {
    expect(parseRls([{ file: "m.sql", sql: mk("auth.uid() = user_id") }])).toEqual([]);
  });

  test("a clause that only MENTIONS the idiom but adds scoping → no warning (conservative)", () => {
    const scoped = mk("auth.uid() is not null and team_id = current_team()");
    expect(parseRls([{ file: "m.sql", sql: scoped }])).toEqual([]);
  });

  test("`using (true)` still wins as HIGH/block (precedence over the authenticated warn)", () => {
    const sql = [
      "create table public.t (id uuid);",
      "alter table public.t enable row level security;",
      "create policy p on public.t for select using (true);",
    ].join("\n");
    const f = parseRls([{ file: "m.sql", sql }]);
    expect(f[0]).toMatchObject({ ruleId: "rls-policy-using-true", severity: "high" });
    expect(verdictOf("rls", f, ts).status).toBe("block");
  });
});

// ── The fail-closed coverage check (CVE-2025-48757: "RLS not found" ≠ "RLS fine") ──

describe("detectSupabaseUsage (pure)", () => {
  test("finds the import and the queried tables", () => {
    const u = detectSupabaseUsage([
      { file: "src/lib/db.ts", code: "import { createClient } from '@supabase/supabase-js';" },
      { file: "src/pages/Dashboard.tsx", code: "const { data } = await supabase.from('clients').select();" },
      { file: "src/pages/Notes.tsx", code: "supabase.from(\"session_notes\").insert(x)" },
    ]);
    expect(u.usesSupabase).toBe(true);
    expect([...u.tables.keys()].sort()).toEqual(["clients", "session_notes"]);
    expect(u.tables.get("clients")).toMatchObject({ file: "src/pages/Dashboard.tsx" });
  });

  test("a package.json dependency alone confirms Supabase usage", () => {
    const u = detectSupabaseUsage([{ file: "src/a.ts", code: "supabase.from('clients').select()" }], true);
    expect(u.usesSupabase).toBe(true);
    expect([...u.tables.keys()]).toEqual(["clients"]);
  });

  test("does NOT treat .from() as a table query when Supabase isn't present (no false positive)", () => {
    const u = detectSupabaseUsage([{ file: "q.ts", code: "knex.from('users').where('id', 1)" }]);
    expect(u.usesSupabase).toBe(false);
    expect(u.tables.size).toBe(0);
  });

  test("detects CDN/client-side Supabase with NO npm dep (the Run-3 blind spot)", () => {
    // The client comes from a CDN <script> + window.supabase global; package.json
    // has no @supabase dep. Each of these markers alone must confirm usage.
    const cdnTag = { file: "views/index.ejs", code: '<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>' };
    const global = { file: "public/app.js", code: "const supabase = window.supabase.createClient(u, k);\nawait supabase.from('feedbacks').insert(x);" };
    const u = detectSupabaseUsage([cdnTag, global]); // pkgHasSupabase = false
    expect(u.usesSupabase).toBe(true);
    expect([...u.tables.keys()]).toEqual(["feedbacks"]);
  });

  test("a SUPABASE_* env name alone (e.g. server.js) confirms usage", () => {
    const u = detectSupabaseUsage([
      { file: "server.js", code: "const url = process.env.SUPABASE_URL;\nsupabase.from('rows')" },
    ]);
    expect(u.usesSupabase).toBe(true);
    expect([...u.tables.keys()]).toEqual(["rows"]);
  });

  test("a .supabase.co project URL confirms usage", () => {
    const u = detectSupabaseUsage([{ file: "config.js", code: "const URL='https://abcd.supabase.co'; db.from('t')" }]);
    expect(u.usesSupabase).toBe(true);
  });

  test("VITE_ / NEXT_PUBLIC_ prefixed env names are still detected", () => {
    expect(detectSupabaseUsage([{ file: "c.ts", code: "import.meta.env.VITE_SUPABASE_URL" }]).usesSupabase).toBe(true);
    expect(detectSupabaseUsage([{ file: "c.ts", code: "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY" }]).usesSupabase).toBe(true);
  });
});

describe("parseRlsCoverage (pure, fail-closed)", () => {
  const usage = (tables: string[]) =>
    detectSupabaseUsage(
      tables.map((t, i) => ({ file: `src/p${i}.ts`, code: `supabase.from('${t}').select()` })),
      true,
    );

  test("a queried table with no RLS migration → CRITICAL rls-missing", () => {
    const f = parseRlsCoverage(usage(["clients", "session_notes"]), new Set(), new Set());
    expect(f).toHaveLength(2);
    expect(f[0]).toMatchObject({ tool: "rls", ruleId: "rls-missing", severity: "critical" });
    expect(f.every((x) => x.message.includes("CVE-2025-48757"))).toBe(true);
  });

  test("queried tables that ARE rls-enabled → no coverage finding", () => {
    const f = parseRlsCoverage(usage(["clients"]), new Set(["clients"]), new Set(["clients"]));
    expect(f).toEqual([]);
  });

  test("a created-but-unprotected table is left to parseRls (no double-report)", () => {
    // created.has(clients) → coverage defers; parseRls would emit rls-disabled.
    const f = parseRlsCoverage(usage(["clients"]), new Set(), new Set(["clients"]));
    expect(f).toEqual([]);
  });

  test("no Supabase usage → nothing required", () => {
    expect(parseRlsCoverage(detectSupabaseUsage([]), new Set(), new Set())).toEqual([]);
  });
});

describe("parseServiceKeyUsage (RLS-reliance — the gate stays honest)", () => {
  const C = (file: string, code: string) => [{ file, code }];

  test("service-role key under a PUBLIC/client env prefix → CRITICAL exposed", () => {
    for (const env of ["NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", "VITE_SUPABASE_SERVICE_ROLE_KEY", "REACT_APP_SUPABASE_SERVICE_ROLE_KEY"]) {
      const f = parseServiceKeyUsage(C("src/client.ts", `const k = import.meta.env.${env};`));
      expect(f).toHaveLength(1);
      expect(f[0]).toMatchObject({ ruleId: "rls-service-key-exposed", severity: "critical" });
    }
  });

  test("server-side service-role key (no public prefix) → MEDIUM bypass warn", () => {
    const f = parseServiceKeyUsage(C("server/db.ts", "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);"));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: "rls-service-key-bypass", severity: "medium" });
  });

  test("a hardcoded sb_secret_ key → bypass", () => {
    expect(parseServiceKeyUsage(C("server/db.ts", 'const k = "sb_secret_9a8Nr5zhncwy39";'))[0]?.ruleId).toBe("rls-service-key-bypass");
  });

  test("an RLS-respecting app (only the anon/publishable key) → no findings", () => {
    expect(parseServiceKeyUsage(C("lib/supabase.ts", "createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);"))).toEqual([]);
  });

  test("exposure outranks bypass in the same file (no double-report)", () => {
    const f = parseServiceKeyUsage(C("x.ts", "const a = NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY; const b = SUPABASE_SERVICE_ROLE_KEY;"));
    expect(f).toHaveLength(1);
    expect(f[0]?.ruleId).toBe("rls-service-key-exposed");
  });
});

describe("runRls end-to-end (§11 fail-closed for rls)", () => {
  const ts = "2026-06-21T00:00:00.000Z";

  test("Supabase app that queries a table but ships NO migration → BLOCK", async () => {
    const dir = await scratch({
      "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2.39.0" } }),
      "src/lib/supabaseClient.ts": "import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient(url, key);",
      "src/pages/Dashboard.tsx": "const { data } = await supabase.from('clients').select('*');",
    });
    const v = await runRls(dir, ts);
    expect(v.status).toBe("block");
    expect(v.findings.some((f) => f.ruleId === "rls-missing" && f.severity === "critical")).toBe(true);
  });

  test("Supabase app with sound RLS policies for every queried table → PASS", async () => {
    const dir = await scratch({
      "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2.39.0" } }),
      "src/lib/supabaseClient.ts": "import { createClient } from '@supabase/supabase-js';",
      "src/pages/Dashboard.tsx": "supabase.from('clients').select('*'); supabase.from('session_notes').select('*');",
      "supabase/migrations/001_init.sql": [
        "create table public.clients (id uuid primary key, therapist_id uuid);",
        "alter table public.clients enable row level security;",
        "create policy own_clients on public.clients for all using (therapist_id = auth.uid());",
        "create table public.session_notes (id uuid primary key, therapist_id uuid);",
        "alter table public.session_notes enable row level security;",
        "create policy own_notes on public.session_notes for all using (therapist_id = auth.uid());",
      ].join("\n"),
    });
    const v = await runRls(dir, ts);
    expect(v.findings).toEqual([]);
    expect(v.status).toBe("pass");
  });

  test("a non-Supabase app with no DB still passes (no false positive)", async () => {
    const dir = await scratch({
      "package.json": JSON.stringify({ dependencies: { react: "^18.0.0" } }),
      "src/App.tsx": "export default function App() { return null; }",
    });
    expect((await runRls(dir, ts)).status).toBe("pass");
  });

  test("CDN/client-side Supabase (no npm dep) + NO migration → BLOCK (blind spot closed)", async () => {
    const dir = await scratch({
      // Express server, Supabase only via a CDN <script> + window.supabase — exactly Run 3.
      "package.json": JSON.stringify({ dependencies: { express: "^4.18.2", ejs: "^3.1.9" } }),
      "server.js": "const url = process.env.SUPABASE_URL; require('express')();",
      "views/index.ejs": '<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>',
      "public/app.js": "const supabase = window.supabase.createClient(u, k);\nawait supabase.from('feedbacks').select('*');",
    });
    const v = await runRls(dir, ts);
    expect(v.status).toBe("block");
    expect(v.findings.some((f) => f.ruleId === "rls-missing" && f.severity === "critical")).toBe(true);
  });

  test("CDN/client-side Supabase WITH a sound migration → PASS (no false fire)", async () => {
    const dir = await scratch({
      "package.json": JSON.stringify({ dependencies: { express: "^4.18.2", ejs: "^3.1.9" } }),
      "views/index.ejs": '<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>',
      "public/app.js": "const supabase = window.supabase.createClient(u, k);\nawait supabase.from('feedbacks').select('*');",
      "supabase/migrations/001.sql": [
        "create table public.feedbacks (id uuid primary key, owner uuid);",
        "alter table public.feedbacks enable row level security;",
        "create policy own on public.feedbacks for select using (auth.uid() = owner);",
      ].join("\n"),
    });
    expect((await runRls(dir, ts)).status).toBe("pass");
  });
});

describe("migration fact extractors (pure)", () => {
  test("rlsEnabledTables and createdTables read across sources", () => {
    const sources = [
      { file: "a.sql", sql: "create table public.clients (id uuid);" },
      { file: "b.sql", sql: "alter table public.clients enable row level security;" },
    ];
    expect([...createdTables(sources)]).toEqual(["clients"]);
    expect([...rlsEnabledTables(sources)]).toEqual(["clients"]);
  });
});

describe("pkgUsesSupabase (I/O)", () => {
  test("true when @supabase/supabase-js is a dependency, false otherwise", async () => {
    const yes = await scratch({ "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2" } }) });
    const no = await scratch({ "package.json": JSON.stringify({ dependencies: { express: "^4" } }) });
    expect(pkgUsesSupabase(yes)).toBe(true);
    expect(pkgUsesSupabase(no)).toBe(false);
  });
});

describe("A5 — static gate hardening (tautologies, WITH CHECK, report-all)", () => {
  const created = (name: string, policies: string) => `create table "${name}" ("id" uuid primary key);\nalter table "${name}" enable row level security;\n${policies}`;

  test("a `using (1=1)` tautology is caught, not just the literal `using (true)`", () => {
    const f = parseRls([{ file: "m.sql", sql: created("notes", `create policy p on "notes" for all using (1=1) with check (1=1);`) }]);
    expect(f.some((x) => x.ruleId === "rls-policy-using-true")).toBe(true);
  });

  test("a too-broad `with check (true)` is caught as a cross-tenant WRITE hole", () => {
    const f = parseRls([{ file: "m.sql", sql: created("notes", `create policy p on "notes" for all using ("tenant_id" = auth_tenant_id()) with check (true);`) }]);
    const wc = f.find((x) => x.ruleId === "rls-policy-check-true");
    expect(wc).toBeTruthy();
    expect(wc!.severity).toBe("high"); // blocking
  });

  test("report-all: a table with BOTH a tautology read and a broad-authenticated policy yields TWO findings", () => {
    const sql = created("notes", `create policy a on "notes" for select using (true);\ncreate policy b on "notes" for all using (auth.uid() is not null) with check (auth.uid() is not null);`);
    const ids = parseRls([{ file: "m.sql", sql }]).map((x) => x.ruleId);
    expect(ids).toContain("rls-policy-using-true");
    expect(ids).toContain("rls-policy-authenticated"); // not collapsed to the first match
  });

  test("audit2 A5: the extended tautology spellings are all caught", () => {
    for (const taut of ["2>1", "not false", "'t'::boolean", "1 is not null", "(select true) is not false", "true::boolean", "0 = 0"]) {
      const f = parseRls([{ file: "m.sql", sql: created("notes", `create policy p on "notes" for all using (${taut}) with check (${taut});`) }]);
      expect(f.some((x) => x.ruleId === "rls-policy-using-true")).toBe(true);
    }
  });

  test("audit2 A5: a real scoped predicate is NOT mistaken for a tautology", () => {
    const f = parseRls([{ file: "m.sql", sql: created("notes", `create policy p on "notes" for all using ("tenant_id" = auth_tenant_id()) with check ("tenant_id" = auth_tenant_id());`) }]);
    expect(f.some((x) => x.ruleId === "rls-policy-using-true")).toBe(false);
    expect(f.some((x) => x.ruleId === "rls-policy-check-true")).toBe(false);
  });

  test("audit2 C-2: `auth.uid() is not null` BLOCKS (high) when the project is multi-tenant", () => {
    const sql = created("notes", `create policy p on "notes" for all using (auth.uid() is not null) with check (auth.uid() is not null);`);
    const f = parseRls([{ file: "m.sql", sql }], { multiTenant: true });
    const authed = f.find((x) => x.ruleId === "rls-policy-authenticated");
    expect(authed?.severity).toBe("high"); // blocking in a multi-tenant app
  });

  test("audit2 C-2: the same policy stays a MEDIUM warn for a single-tenant app", () => {
    const sql = created("notes", `create policy p on "notes" for all using (auth.uid() is not null) with check (auth.uid() is not null);`);
    const f = parseRls([{ file: "m.sql", sql }], { multiTenant: false });
    expect(f.find((x) => x.ruleId === "rls-policy-authenticated")?.severity).toBe("medium");
  });
});
