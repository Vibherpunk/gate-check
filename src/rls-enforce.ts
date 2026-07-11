/**
 * The RLS ENFORCEMENT gate — the keystone the audit demanded. Every other RLS check reads policy text;
 * NONE proves the database actually DENIES a cross-tenant read. This one does: it applies the generated
 * migrations to embedded Postgres (pglite), replicates Supabase's default table grants so RLS is the
 * ONLY thing gating access, seeds TWO tenants, then — as tenant A's `authenticated` session and as an
 * anonymous session — asserts A can neither read, update, delete, nor insert tenant B's rows for every
 * isolated entity. A leak is a BLOCKING finding; a harness ERROR fails CLOSED (blocks). A project with
 * no data model is "n/a" (nothing to seed) — the static rls gate is the backstop there, not a fake pass.
 *
 * This is the difference between "the policy text looks right" (what the author imagined) and "the
 * database refuses the attack" (what is true). It is also the generator's real regression harness.
 *
 * Note: pglite enforces RLS for non-superuser roles (confirmed), and `auth.uid()` resolves from the
 * `request.jwt.claim.sub` GUC (see SUPABASE_STUBS) — so switching identity is `set_config` + `SET ROLE`.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { coerceDataModel, type DataModel, type Entity, type Field } from "./backend-model.ts";
import type { Finding, Gate, GateVerdict } from "./types.ts";
import { notApplicable, verdictOf } from "./types.ts";
import { SUPABASE_STUBS, neutralize } from "./migrate.ts";

// Fixed, valid UUIDs for the two-tenant fixture. Tenant root rows ARE the tenant ids.
const TA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const UA = "a1111111-1111-4111-8111-111111111111"; // auth uid (tenant A user)
const UB = "b1111111-1111-4111-8111-111111111111";
const MEMA = "a2222222-2222-4222-8222-222222222222"; // membership-row ids
const MEMB = "b2222222-2222-4222-8222-222222222222";

type T = "A" | "B";

const sqlStr = (s: string) => `'${s.replace(/'/g, "''")}'`;

function valueForType(t: Field["type"]): string {
  switch (t) {
    case "uuid": return "gen_random_uuid()";
    case "text": return "'seed'";
    case "text[]": return "'{}'::text[]";
    case "integer": return "1";
    case "numeric": return "1";
    case "boolean": return "true";
    case "timestamptz": return "now()";
    case "date": return "current_date";
    case "jsonb": return "'{}'::jsonb";
    default: return "'seed'";
  }
}

/** Parents before children, so FK targets exist when a row is seeded. Cycles go last (best-effort). */
function ordered(model: DataModel): Entity[] {
  const byName = new Map(model.entities.map((e) => [e.name, e] as const));
  const done = new Set<string>();
  const out: Entity[] = [];
  let progress = true;
  while (out.length < model.entities.length && progress) {
    progress = false;
    for (const e of model.entities) {
      if (done.has(e.name)) continue;
      const deps = e.fields.filter((f) => f.references && byName.has(f.references) && f.references !== e.name).map((f) => f.references!);
      if (deps.every((d) => done.has(d))) {
        out.push(e);
        done.add(e.name);
        progress = true;
      }
    }
  }
  for (const e of model.entities) if (!done.has(e.name)) out.push(e);
  return out;
}

function idFor(model: DataModel, e: Entity, t: T): string {
  if (e.name === model.tenantEntity) return t === "A" ? TA : TB;
  if (e.name === model.membershipEntity) return t === "A" ? MEMA : MEMB;
  const i = model.entities.findIndex((x) => x.name === e.name);
  const p = String(i + 1).padStart(2, "0");
  return t === "A" ? `a${p}00000-0000-4000-8000-000000000000` : `b${p}00000-0000-4000-8000-000000000000`;
}

/** Build an INSERT for entity `e` belonging to tenant `t`. `idVal` overrides the row id (a fresh id for
 *  the cross-tenant write probe). Mirrors the generator's synthesized columns (id, membership auth/
 *  tenant/role) so the row satisfies NOT NULL + FK constraints; values are RLS-irrelevant otherwise. */
function insertRow(model: DataModel, e: Entity, t: T, idVal: string): string {
  const cols: string[] = [`"id"`];
  const vals: string[] = [`'${idVal}'`];
  const present = new Set(e.fields.map((f) => f.name));
  const tenantId = t === "A" ? TA : TB;
  // The generated table strips model fields named `id`/`createdAt` (the generator synthesizes those —
  // see normalizeFields), so the harness must too, or a model that lists an explicit `id` (real LLM
  // output) yields "column id specified more than once". Dedup by name, case-folded.
  const seen = new Set<string>(["id", "createdat"]);
  const push = (c: string, v: string) => {
    const k = c.toLowerCase();
    if (seen.has(k)) return;
    seen.add(k);
    cols.push(`"${c}"`);
    vals.push(v);
  };
  if (e.name === model.membershipEntity) {
    if (!present.has("authUserId")) push("authUserId", `'${t === "A" ? UA : UB}'`);
    if (!present.has(model.tenantField) && model.tenantEntity) push(model.tenantField, `'${tenantId}'`);
    if (!present.has(model.roleField)) push(model.roleField, sqlStr(model.adminRole));
  }
  for (const f of e.fields) {
    let v: string;
    if (f.references) {
      const ref = model.entities.find((x) => x.name === f.references);
      v = ref ? `'${idFor(model, ref, t)}'` : "gen_random_uuid()";
    } else if (f.name === model.tenantField && model.tenantEntity) {
      v = `'${tenantId}'`;
    } else if (f.name === "authUserId") {
      v = `'${t === "A" ? UA : UB}'`;
    } else if (f.name === model.roleField && e.name === model.membershipEntity) {
      v = sqlStr(model.adminRole);
    } else {
      v = valueForType(f.type);
    }
    push(f.name, v);
  }
  return `insert into "${e.name}" (${cols.join(", ")}) values (${vals.join(", ")})`;
}

const leak = (e: Entity, op: string, message: string): Finding => ({ tool: "rls-enforce", ruleId: `cross-tenant-${op}`, severity: "high", file: "supabase/migrations/0003_rls.sql", message });
const note = (message: string): Finding => ({ tool: "rls-enforce", ruleId: "probe-inconclusive", severity: "medium", file: "supabase/migrations", message });

export interface EnforceOptions {
  ranAt?: string;
}

/** Run the enforcement harness over a generated project + its data model. Returns a BLOCKING verdict for
 *  any cross-tenant access that succeeds, or for a harness error (fail-closed). */
export async function runRlsEnforcement(projectPath: string, model: DataModel, opts: EnforceOptions = {}): Promise<GateVerdict> {
  const ranAt = opts.ranAt ?? new Date().toISOString();
  const dir = join(projectPath, "supabase", "migrations");
  if (!existsSync(dir) || !model.entities.length || !model.membershipEntity) return notApplicable("rls-enforce", ranAt);
  const migs = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort().map((f) => readFileSync(join(dir, f), "utf8"));

  const { PGlite } = await import("@electric-sql/pglite");
  const db = new PGlite();
  const findings: Finding[] = [];
  const scalar = async (sql: string): Promise<number> => {
    const r = await db.query<{ n: number }>(sql);
    return Number((r.rows[0] as { n?: number } | undefined)?.n ?? 0);
  };
  const become = (role: "authenticated" | "anon", sub: string) => db.exec(`reset role; select set_config('request.jwt.claim.sub', '${sub}', false); set role ${role};`);

  try {
    await db.exec(SUPABASE_STUBS);
    await db.exec(`set statement_timeout = '20s';`).catch(() => {}); // best-effort build-DoS guard (audit2 D)
    for (const sql of migs) await db.exec(neutralize(sql));
    // Replicate Supabase's default grants so RLS — not a missing GRANT — is the ONLY access control.
    await db.exec(`grant usage on schema public to anon, authenticated; grant select, insert, update, delete on all tables in schema public to anon, authenticated;`);
    // Seed both tenants as the superuser (RLS bypassed) so there is cross-tenant data to (fail to) reach.
    for (const e of ordered(model)) {
      await db.exec(insertRow(model, e, "A", idFor(model, e, "A")));
      await db.exec(insertRow(model, e, "B", idFor(model, e, "B")));
    }

    // C-2 (audit2): does this entity carry a tenant column? An `access:"auth"` table that does is
    // tenant data mislabeled as "any authenticated user" — the generator emits a permissive
    // `auth.uid() is not null` policy for it, which leaks ACROSS tenants. Probe those too.
    const hasTenantColumn = (e: Entity): boolean =>
      (!!model.tenantField && e.fields.some((f) => f.name === model.tenantField)) ||
      (!!model.tenantEntity && e.fields.some((f) => f.references === model.tenantEntity));
    // M-5 (audit3): a per-user owner column the harness can seed to a known user (authUserId is the
    // generator's standard owner column + is special-cased in insertRow). An access:"auth" table with
    // one but NO tenant column is per-user data mislabeled as shared — any authed user reads any other's.
    const hasOwnerColumn = (e: Entity): boolean => e.fields.some((f) => f.name === "authUserId" || f.name === e.ownerField);

    for (const e of model.entities) {
      if (e.access === "public") continue; // world-readable by design
      const idB = idFor(model, e, "B");
      const isolated = e.access === "owner" || e.access === "tenant" || e.access === "tenant-admin";
      const authTenantScoped = e.access === "auth" && hasTenantColumn(e);
      const authUserScoped = e.access === "auth" && !hasTenantColumn(e) && hasOwnerColumn(e);
      const mislabel = authTenantScoped
        ? ` — "${e.name}" is access:"auth" but carries a tenant column; relabel it "tenant"/"owner" so RLS scopes rows to the caller's tenant`
        : authUserScoped
          ? ` — "${e.name}" is access:"auth" but has a per-user owner column; any authenticated user can read another user's rows — use access:"owner"`
          : "";

      // C-3 (audit3) standalone: an access:"auth" table that is actually tenant/user-scoped is mislabeled
      // even when its policy happens to be correct — surface it as a non-blocking advisory regardless of
      // the probe outcome, so the labeling error is visible (not only as a side-note on a leak finding).
      if (authTenantScoped || authUserScoped) {
        findings.push({ tool: "rls-enforce", ruleId: "access-auth-mislabel", severity: "low", file: "supabase/migrations", message: `"${e.name}" is access:"auth" but ${authTenantScoped ? "carries a tenant column" : "has a per-user owner column"} — if it holds per-${authTenantScoped ? "tenant" : "user"} data, relabel it "${authTenantScoped ? "tenant" : "owner"}" so RLS scopes it (access:"auth" means any authenticated user can read every row).` });
      }

      if (isolated || authTenantScoped || authUserScoped) {
        // READ: tenant A must not see tenant B's row.
        await become("authenticated", UA);
        if ((await scalar(`select count(*)::int as n from "${e.name}" where "id" = '${idB}'`)) > 0) findings.push(leak(e, "read", `tenant isolation FAILS: an authenticated user of tenant A can SELECT tenant B's "${e.name}" row.${mislabel}`));

        // UPDATE / DELETE: rolled back so the probe is non-destructive even on a leak.
        await db.exec("begin");
        const upd = await scalar(`with u as (update "${e.name}" set "id" = "id" where "id" = '${idB}' returning 1) select count(*)::int as n from u`);
        const del = await scalar(`with d as (delete from "${e.name}" where "id" = '${idB}' returning 1) select count(*)::int as n from d`);
        await db.exec("rollback");
        if (upd > 0) findings.push(leak(e, "update", `tenant isolation FAILS: tenant A can UPDATE tenant B's "${e.name}" row.`));
        if (del > 0) findings.push(leak(e, "delete", `tenant isolation FAILS: tenant A can DELETE tenant B's "${e.name}" row.`));

        // INSERT a row belonging to tenant B while acting as A → must be blocked by WITH CHECK.
        const crossId = `c${String(model.entities.indexOf(e) + 1).padStart(2, "0")}00000-0000-4000-8000-000000000000`;
        await become("authenticated", UA);
        try {
          await db.query(insertRow(model, e, "B", crossId));
          findings.push(leak(e, "insert", `WRITE isolation FAILS: tenant A can INSERT a row into tenant B's "${e.name}" (missing or too-weak WITH CHECK).${mislabel}`));
          await db.exec(`reset role; delete from "${e.name}" where "id" = '${crossId}';`); // clean up the leaked row
        } catch (err) {
          const m = String(err instanceof Error ? err.message : err);
          if (!/row-level security|violates|permission denied|policy/i.test(m)) findings.push(note(`cross-tenant INSERT probe inconclusive on "${e.name}": ${m.split("\n")[0]?.slice(0, 140)}`));
        }
      }

      // ANON: an unauthenticated user must read nothing from a non-public table.
      await become("anon", "");
      if ((await scalar(`select count(*)::int as n from "${e.name}"`)) > 0) findings.push(leak(e, "anon-read", `PUBLIC EXPOSURE: an anonymous (logged-out) user can read "${e.name}" — the CVE-2025-48757 class.`));
    }
    await db.exec("reset role;");
  } catch (e) {
    // Fail CLOSED — "could not verify" is a block, never a pass.
    findings.push({ tool: "rls-enforce", ruleId: "enforcement-error", severity: "high", file: "supabase/migrations", message: `RLS enforcement could NOT be verified (failing closed): ${String(e instanceof Error ? e.message : e).split("\n")[0]?.slice(0, 200)}` });
  } finally {
    await db.close();
  }
  return verdictOf("rls-enforce", findings, ranAt);
}

/** Gate wrapper: load the model the generator persisted, then prove isolation. When no model is present
 *  (a hand-written app that didn't go through the generator) the harness can't seed — it returns an
 *  empty verdict here; B3 gives that the distinct "not-applicable" status so it can't count as verified. */
export const rlsEnforceGate: Gate = {
  name: "rls-enforce",
  run: async (projectPath: string): Promise<GateVerdict> => {
    const ranAt = new Date().toISOString();
    const modelPath = join(projectPath, ".vibehard", "datamodel.json");
    if (!existsSync(modelPath)) return notApplicable("rls-enforce", ranAt);
    let model: DataModel;
    try {
      model = coerceDataModel(JSON.parse(readFileSync(modelPath, "utf8")));
    } catch {
      return notApplicable("rls-enforce", ranAt);
    }
    return runRlsEnforcement(projectPath, model, { ranAt });
  },
};
