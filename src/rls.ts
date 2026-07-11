/**
 * RLS gate — static analysis of Supabase access control. Two complementary checks,
 * both modelled on CVE-2025-48757 (170+ Lovable apps leaked data because a table's
 * REST API was reachable with no Row-Level Security) (PROJECT_BRIEF.md §2, §5):
 *
 *   1. MIGRATION check (`parseRls`): every public table a migration CREATES must
 *      have RLS enabled AND a policy that isn't `using (true)`.
 *   2. COVERAGE check (`parseRlsCoverage`): every table the APP QUERIES (via the
 *      Supabase client `.from('x')`) must be protected by RLS in a migration. An
 *      app that talks to Supabase but ships no RLS for a table it reads is the
 *      literal CVE pattern — and the dangerous default: "no RLS migration found"
 *      is NOT "RLS is fine". So a missing migration FAILS CLOSED (§11, §16/§24),
 *      rather than passing vacuously because there was nothing to parse.
 *
 * Pure (no container, no network): the parsers are functions over text and are
 * fully unit-tested; the only I/O is reading migration + source files off disk.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Glob } from "bun";
import type { Finding, GateVerdict } from "./types.ts";
import { verdictOf } from "./types.ts";
import { DERIVED_DIRS } from "./scan-scope.ts";

/** One migration file's text, tagged with its (relative) path for finding attribution. */
export interface SqlSource {
  file: string;
  sql: string;
}

/** One app source file's text, tagged with its (relative) path. */
export interface CodeSource {
  file: string;
  code: string;
}

/** 1-based line number of a character offset within `text`. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === "\n") line++;
  return line;
}

const DERIVED = new Set<string>(DERIVED_DIRS);
// Scan code AND server-rendered templates: a CDN-loaded Supabase client lives in a
// `<script src>` in .html/.ejs, and inline `.from()` queries can too — missing those
// would re-open the vacuous-RLS hole for client-side apps (where the anon key ships
// to the browser, so RLS is the ONLY protection).
const CODE_GLOB = "**/*.{ts,tsx,js,jsx,mjs,cjs,vue,svelte,astro,html,htm,ejs,hbs,handlebars,pug}";
const MAX_CODE_BYTES = 200_000;

/** Markers that an app talks to a Supabase Postgres (the surface RLS protects),
 *  covering BOTH npm and CDN/global usage. Each is Supabase-specific enough not to
 *  fire on unrelated code. */
const SUPABASE_MARKERS: RegExp[] = [
  /@supabase\/supabase-js/, //                       npm import OR a CDN <script src=...>
  /\bwindow\.supabase\b/, //                          CDN UMD global (window.supabase.createClient)
  /[a-z0-9-]+\.supabase\.co\b/i, //                   a Supabase project URL
  /SUPABASE_(?:URL|ANON_KEY|SERVICE_ROLE_KEY|KEY)\b/, // Supabase env names (incl. VITE_/NEXT_PUBLIC_ prefixes)
];

/** Does this source show any sign of using Supabase? */
function signalsSupabase(code: string): boolean {
  return SUPABASE_MARKERS.some((re) => re.test(code));
}

// ── Migration facts (shared by both checks) ──────────────────────────────────

/** Tables with `alter table ... enable row level security`, anywhere in the set. */
export function rlsEnabledTables(sources: SqlSource[]): Set<string> {
  const combined = sources.map((s) => s.sql).join("\n").toLowerCase();
  const out = new Set<string>();
  for (const m of combined.matchAll(
    /alter table\s+(?:if exists\s+)?(?:"?public"?\s*\.\s*)?"?(\w+)"?\s+enable row level security/g,
  )) {
    if (m[1]) out.add(m[1]);
  }
  return out;
}

/** A predicate that authorizes EVERY caller — `true` and its common tautology spellings. The literal
 *  `using (true)` was trivially evaded by `1=1` / `(select true)` (audit H2), and audit2 A5 added the
 *  `2>1` / `not false` / `'t'::boolean` / `1 is not null` / `(select true) is not false` family — all
 *  caught here so a one-character respelling can't slip a world-readable policy past the gate. */
const TAUTOLOGY = String.raw`(?:` +
  String.raw`true(?:::bool(?:ean)?)?` + // true, true::bool, true::boolean
  String.raw`|'(?:t|true)'(?:::bool(?:ean)?)?` + // 't', 'true', 't'::boolean
  String.raw`|\d+\s*(?:=|<>|!=|>=|<=|>|<)\s*\d+` + // constant comparison: 1=1, 2>1, 0<1, …
  String.raw`|not\s+false` + // not false
  String.raw`|\(\s*select\s+true\s*\)(?:\s+is\s+not\s+false)?` + // (select true), (select true) is not false
  String.raw`|(?:true|\d+|'(?:t|true)')\s+is\s+not\s+null` + // a non-null constant is never null
  String.raw`|(?:true|\d+|null|'(?:t|true)')\s+is\s+not\s+false` + // … is not false
  String.raw`)`;

/** Tables whose USING clause is a tautology (authorizes every caller → world-readable). */
function permissiveTables(sources: SqlSource[]): Set<string> {
  const combined = sources.map((s) => s.sql).join("\n").toLowerCase();
  const out = new Set<string>();
  for (const m of combined.matchAll(new RegExp(String.raw`create policy[^;]*?\bon\s+(?:"?public"?\s*\.\s*)?"?(\w+)"?[^;]*?using\s*\(\s*${TAUTOLOGY}\s*\)`, "gs"))) {
    if (m[1]) out.add(m[1]);
  }
  return out;
}

/** Tables whose WITH CHECK clause is a tautology — reads may be scoped, but ANY caller can INSERT/UPDATE
 *  rows into ANOTHER tenant (the cross-tenant WRITE hole the A1 enforcement gate proved is real). The
 *  static gate never looked at WITH CHECK before (audit C5). A `for select` policy has none, so this
 *  only fires on FOR ALL/INSERT/UPDATE — exactly where a broad write check is dangerous. */
function broadWriteCheckTables(sources: SqlSource[]): Set<string> {
  const combined = sources.map((s) => s.sql).join("\n").toLowerCase();
  const out = new Set<string>();
  for (const m of combined.matchAll(new RegExp(String.raw`create policy[^;]*?\bon\s+(?:"?public"?\s*\.\s*)?"?(\w+)"?[^;]*?with\s+check\s*\(\s*${TAUTOLOGY}\s*\)`, "gs"))) {
    if (m[1]) out.add(m[1]);
  }
  return out;
}

/**
 * Tables whose `using` clause authorizes ANY authenticated user
 * (`auth.uid() is not null` / `auth.role() = 'authenticated'`) instead of scoping
 * rows to their owner. This is NOT the CVE pattern — anonymous callers are still
 * blocked — so it's a WARN, not a block: legitimate for a single-tenant app, but
 * in a multi-tenant one every logged-in user can read every row. We match only
 * these two distinctive idioms (a clause with extra conditions, e.g.
 * `... is not null and team_id = ...`, won't match — it's likely scoped). It's a
 * judgment call, so we surface it for review rather than decide it.
 */
function broadAuthenticatedTables(sources: SqlSource[]): Set<string> {
  const combined = sources.map((s) => s.sql).join("\n").toLowerCase();
  const out = new Set<string>();
  for (const m of combined.matchAll(
    /create policy[^;]*?\bon\s+(?:"?public"?\s*\.\s*)?"?(\w+)"?[^;]*?using\s*\(\s*(?:auth\.uid\(\)\s+is\s+not\s+null|auth\.role\(\)\s*=\s*'authenticated'|'authenticated'\s*=\s*auth\.role\(\))\s*\)/gs,
  )) {
    if (m[1]) out.add(m[1]);
  }
  return out;
}

/** Tables a migration CREATEs (used to avoid double-reporting in the coverage check). */
export function createdTables(sources: SqlSource[]): Set<string> {
  const out = new Set<string>();
  for (const src of sources) {
    for (const m of src.sql.matchAll(/create table\s+(?:if not exists\s+)?(?:"?public"?\s*\.\s*)?"?(\w+)"?/gi)) {
      if (m[1]) out.add(m[1].toLowerCase());
    }
  }
  return out;
}

// ── Check 1: migration analysis ──────────────────────────────────────────────

/**
 * Pure: migration SQL → Finding[]. A created table with no `enable row level
 * security` → CRITICAL (its REST API is open); a `using (true)` policy → HIGH
 * (authorizes every caller). Each table reported once, attributed to its create.
 */
export function parseRls(sources: SqlSource[], opts: { multiTenant?: boolean } = {}): Finding[] {
  const rlsOn = rlsEnabledTables(sources);
  const permissive = permissiveTables(sources);
  const broadWriteCheck = broadWriteCheckTables(sources);
  const broadAuthed = broadAuthenticatedTables(sources);

  const findings: Finding[] = [];
  const seen = new Set<string>();
  const createRe = /create table\s+(?:if not exists\s+)?(?:"?public"?\s*\.\s*)?"?(\w+)"?/gi;

  for (const src of sources) {
    for (const m of src.sql.matchAll(createRe)) {
      const table = m[1]?.toLowerCase();
      if (!table || seen.has(table)) continue;
      seen.add(table);
      const line = lineAt(src.sql, m.index ?? 0);
      // Report EVERY applicable finding for a table, not just the first (audit H3): a fix to one hole
      // must not hide a second. RLS-off makes policies moot, so when it's off we report only that.
      if (!rlsOn.has(table)) {
        findings.push({ tool: "rls", ruleId: "rls-disabled", severity: "critical", file: src.file, line, message: `RLS not enabled on public.${table} — Supabase exposes this table's REST API to the world` });
        continue;
      }
      if (permissive.has(table)) findings.push({ tool: "rls", ruleId: "rls-policy-using-true", severity: "high", file: src.file, line, message: `RLS read policy is a tautology (\`using (true)\` / \`1=1\`) on public.${table} — authorizes every caller, leaks all rows` });
      if (broadWriteCheck.has(table)) findings.push({ tool: "rls", ruleId: "rls-policy-check-true", severity: "high", file: src.file, line, message: `RLS WITH CHECK is a tautology on public.${table} — reads may be scoped, but ANY caller can INSERT/UPDATE rows into another tenant (cross-tenant write)` });
      if (broadAuthed.has(table)) {
        // C-2 (audit2): "any authenticated user" is a WARN for a single-tenant app, but in a
        // multi-tenant one it's a cross-tenant leak (every logged-in user of every tenant reads
        // every row) → escalate to blocking when the project declares a tenant/membership model.
        const sev: Finding["severity"] = opts.multiTenant ? "high" : "medium";
        const message = opts.multiTenant
          ? `RLS policy on public.${table} authorizes ANY authenticated user (auth.uid() is not null) in a MULTI-TENANT app — every logged-in user of every tenant can read all rows (cross-tenant leak). Scope the policy to the caller's tenant/owner, not merely "logged in".`
          : `RLS policy on public.${table} authorizes any authenticated user (auth.uid() is not null) — every logged-in user can read all rows; confirm this table is shared, not per-tenant (the rls-enforce gate proves cross-tenant isolation when a data model is present)`;
        findings.push({ tool: "rls", ruleId: "rls-policy-authenticated", severity: sev, file: src.file, line, message });
      }
    }
  }
  return findings;
}

// ── Check 2: client-usage coverage (the fail-closed fix) ─────────────────────

/** What the app's source reveals about its Supabase data surface. */
export interface SupabaseUsage {
  /** True if the project depends on / imports @supabase/supabase-js. */
  usesSupabase: boolean;
  /** table name → first `.from('table')` call site, for attribution. */
  tables: Map<string, { file: string; line: number }>;
}

/**
 * Pure: app source (+ whether package.json depends on supabase) → the set of
 * tables the client queries via `.from('x')`. We only trust `.from()` as a table
 * query once Supabase is confirmed (npm import/dependency, CDN global, project URL,
 * or a SUPABASE_* env name — see SUPABASE_MARKERS), so we don't mistake an unrelated
 * `.from()` (knex, RxJS, Array.from) for a Supabase table, and we DO catch the
 * CDN/client-side case where the client never appears in package.json.
 */
export function detectSupabaseUsage(sources: CodeSource[], pkgHasSupabase = false): SupabaseUsage {
  let usesSupabase = pkgHasSupabase;
  for (const { code } of sources) {
    if (signalsSupabase(code)) {
      usesSupabase = true;
      break;
    }
  }
  const tables = new Map<string, { file: string; line: number }>();
  if (!usesSupabase) return { usesSupabase, tables };

  const fromRe = /\.from\(\s*['"`]([A-Za-z_]\w*)['"`]\s*\)/g;
  for (const { file, code } of sources) {
    for (const m of code.matchAll(fromRe)) {
      const table = m[1]?.toLowerCase();
      if (table && !tables.has(table)) tables.set(table, { file, line: lineAt(code, m.index ?? 0) });
    }
  }
  return { usesSupabase, tables };
}

/**
 * Pure: every queried table that is NOT protected by RLS in a migration → a
 * CRITICAL `rls-missing` finding. This is the fail-closed half: "no migration" or
 * "migration doesn't cover this table" must BLOCK, not pass. Tables a migration
 * created are skipped here — `parseRls` already adjudicates those (no double-count).
 */
export function parseRlsCoverage(
  usage: SupabaseUsage,
  rlsOn: Set<string>,
  created: Set<string>,
): Finding[] {
  if (!usage.usesSupabase) return [];
  const findings: Finding[] = [];
  for (const [table, at] of [...usage.tables].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (rlsOn.has(table) || created.has(table)) continue;
    findings.push({
      tool: "rls",
      ruleId: "rls-missing",
      severity: "critical",
      file: at.file,
      line: at.line,
      message: `the app queries Supabase table \`${table}\` but no migration enables row level security on it — its REST API is open to the world (CVE-2025-48757: "RLS not found" is not "RLS fine")`,
    });
  }
  return findings;
}

// ── Check 3: RLS-RELIANCE — the app must rely on RLS, not bypass it ───────────
// The whole guarantee is "the data is protected by RLS, verified live." That only
// holds if the APP actually goes THROUGH RLS. The service-role key BYPASSES it, so:
//   • a service-role key under a CLIENT env prefix ships it to the browser → CRITICAL;
//   • any service-role data path means RLS isn't the boundary there → WARN to review.
// This is what keeps the gate honest for ANY language on Supabase (Go/Swift/Python):
// without it, "we support that stack" is theater the moment an app grabs the service key.

/** A service-role key under a CLIENT-bundled env prefix (Next/Vite/CRA/Svelte/Expo/…) — shipped to the browser. */
const PUBLIC_ENV_SERVICE_KEY = /\b(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP|EXPO_PUBLIC|GATSBY|NUXT_PUBLIC)_[A-Z0-9_]*SERVICE_ROLE/;
/** A reference to the service-role key — the env name, or the `sb_secret_` key format. */
const SERVICE_KEY_REF = /\bSUPABASE_SERVICE_ROLE_KEY\b|\bsb_secret_[A-Za-z0-9]{6,}/;

/** Pure: app source → RLS-reliance findings (service-key exposure / bypass). */
export function parseServiceKeyUsage(sources: CodeSource[]): Finding[] {
  const findings: Finding[] = [];
  for (const { file, code } of sources) {
    const exposed = PUBLIC_ENV_SERVICE_KEY.exec(code);
    if (exposed) {
      findings.push({
        tool: "rls",
        ruleId: "rls-service-key-exposed",
        severity: "critical",
        file,
        line: lineAt(code, exposed.index),
        message: `the Supabase service-role key is exposed to the browser here (a public/client env prefix) — that key BYPASSES Row-Level Security, handing full database access to every visitor`,
      });
      continue; // the exposure is the real problem; don't also warn on the same file
    }
    const ref = SERVICE_KEY_REF.exec(code);
    if (ref) {
      findings.push({
        tool: "rls",
        ruleId: "rls-service-key-bypass",
        severity: "medium", // WARN: a legitimate admin path can use it, but the RLS guarantee does NOT cover it
        file,
        line: lineAt(code, ref.index),
        message: `the service-role key is used here — it BYPASSES Row-Level Security, so the per-tenant RLS guarantee does NOT cover this data path; keep it admin-only (server-side), or access user data with the user's own token through RLS, never the service key`,
      });
    }
  }
  return findings;
}

// ── I/O ──────────────────────────────────────────────────────────────────────

/** Read `<projectPath>/supabase/migrations/*.sql` into typed sources. */
export async function readMigrations(projectPath: string): Promise<SqlSource[]> {
  const dir = join(projectPath, "supabase", "migrations");
  // No migrations dir → readMigrations returns []. That alone no longer means
  // "pass": the coverage check decides, using what the app actually queries.
  if (!existsSync(dir)) return [];
  const glob = new Glob("*.sql");
  const sources: SqlSource[] = [];
  for await (const rel of glob.scan({ cwd: dir })) {
    const sql = await Bun.file(join(dir, rel)).text();
    sources.push({ file: join("supabase", "migrations", rel), sql });
  }
  sources.sort((a, b) => a.file.localeCompare(b.file));
  return sources;
}

/** Read the app's authored source (excluding derived dirs) for usage analysis. */
export async function readAppSources(projectPath: string): Promise<CodeSource[]> {
  const glob = new Glob(CODE_GLOB);
  const out: CodeSource[] = [];
  for await (const rel of glob.scan({ cwd: projectPath, dot: false })) {
    if (rel.split("/").some((seg) => DERIVED.has(seg))) continue;
    try {
      const code = await Bun.file(join(projectPath, rel)).text();
      if (code.length <= MAX_CODE_BYTES) out.push({ file: rel, code });
    } catch {
      /* unreadable file → skip */
    }
  }
  return out;
}

/** C-2 (audit2): is this a multi-tenant project? The generator persists a data model; a
 *  membership or tenant entity means "any authenticated user" policies leak across tenants, so the
 *  static gate escalates that finding to blocking. No model (hand-written app) → treat as single-tenant. */
export function isMultiTenantProject(projectPath: string): boolean {
  const p = join(projectPath, ".vibehard", "datamodel.json");
  if (!existsSync(p)) return false;
  try {
    const m = JSON.parse(readFileSync(p, "utf8")) as { membershipEntity?: unknown; tenantEntity?: unknown };
    return Boolean(m.membershipEntity || m.tenantEntity);
  } catch {
    return false;
  }
}

/** Does package.json declare a dependency on the Supabase client? */
export function pkgUsesSupabase(projectPath: string): boolean {
  const p = join(projectPath, "package.json");
  if (!existsSync(p)) return false;
  try {
    const pkg = JSON.parse(readFileSync(p, "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    return Object.keys(deps).some((d) => d === "@supabase/supabase-js" || d.startsWith("@supabase/"));
  } catch {
    return false;
  }
}

/** Run the static RLS check (migrations + client-usage coverage) against `projectPath`. */
export async function runRls(
  projectPath: string,
  ranAt: string = new Date().toISOString(),
): Promise<GateVerdict> {
  const sources = await readMigrations(projectPath);
  const appSources = await readAppSources(projectPath);
  const usage = detectSupabaseUsage(appSources, pkgUsesSupabase(projectPath));
  const findings = [
    ...parseRls(sources, { multiTenant: isMultiTenantProject(projectPath) }),
    ...parseRlsCoverage(usage, rlsEnabledTables(sources), createdTables(sources)),
    ...(usage.usesSupabase ? parseServiceKeyUsage(appSources) : []),
  ];
  return verdictOf("rls", findings, ranAt);
}

export const rlsGate = { name: "rls", run: (p: string) => runRls(p) };
