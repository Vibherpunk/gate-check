/**
 * VENDORED (2026-07-10 extraction), merged from VibeHard's `src/spec/spec.ts` + `src/spec/coerce.ts`
 * — NOT the full `src/spec/index.ts` barrel, which also re-exports VibeHard's LLM-driven front-half
 * intake/interview pipeline (`intake.ts`, `intake-llm.ts`, `interview.ts`, `brief.ts`) that has
 * nothing to do with gates. `compliance`/`pii`/`prod-readiness`/`verify` only need the classification
 * types (`SensitiveClass`/`Tenancy`/`DeployTarget`/`Rigor`) and the trust-boundary coercer
 * (`coerceSpec`) to read VibeHard's `.vibehard/spec.json`, plus `decideRigor` for verify's rigor gate.
 * Kept as an independent copy: this contract is owned by VibeHard's front-half, and gate-check is
 * the guest borrowing a slice of it, not the owner (same reasoning as `backend-model.ts`).
 *
 * ---- Original header, src/spec/spec.ts ----
 * The PRD — the front-half's durable, schema-validated spec (PROJECT_BRIEF.md §22,
 * §15 "scoped + architected"). `decideRigor` — §16 adaptive rigor: prototype (skip ceremony)
 * vs production (full PRD/architecture/verify/refactor), decided deterministically from the
 * spec's own signals.
 *
 * ---- Original header, src/spec/coerce.ts ----
 * The PRD trust boundary (PROJECT_BRIEF.md §11: the LLM proposes, deterministic code disposes).
 * `coerceSpec` forces arbitrary parsed JSON into a valid `Spec` — clamping enums, coercing types,
 * filling conservative defaults (unknown auth → "none", unknown tenancy → "single-user"), so a
 * malformed or adversarial draft can never produce an invalid spec a reader then mis-judges. Pure.
 */

export type SensitiveClass = "none" | "pii" | "phi" | "financial" | "credentials";
/** How many distinct owners share the app's data — drives the isolation expectation. */
export type Tenancy = "single-user" | "single-tenant" | "multi-tenant";
/** Where the built app is meant to run — a live hosted URL, or code the user downloads and
 *  runs on their own machine. Drives the `verify` gate's check and whether the build is downloadable. */
export type DeployTarget = "hosted-app" | "downloadable-tool";
export type Rigor = "prototype" | "production";

export interface DataEntity {
  name: string;
  fields: string[];
  /** does this entity hold sensitive data (PII/PHI/financial/credentials)? */
  sensitive: boolean;
}

/** The structured spec the front-half produces and the back-half builds against. */
export interface Spec {
  name: string;
  summary: string;
  features: string[];
  users: string; // who uses it, in plain words
  tenancy: Tenancy;
  deployTarget: DeployTarget; // drives the verify gate's boot check and whether the build is downloadable
  auth: string; // "none" | "email-password" | "oauth" | "sso" | …
  storesData: boolean; // does the app persist data at all?
  dataEntities: DataEntity[];
  sensitiveData: SensitiveClass[]; // data classification (§21 control 1)
  realUsers: boolean; // rigor signal — not a throwaway
  maintained: boolean; // rigor signal — lives over time
  refinements?: { at: string; change: string }[]; // post-build change trail; absent on fresh specs
}

/** True if the spec involves sensitive data, by classification OR a flagged entity. */
export function isSensitive(spec: Spec): boolean {
  return spec.sensitiveData.some((c) => c !== "none") || spec.dataEntities.some((e) => e.sensitive);
}

/**
 * Pure: §16 adaptive rigor. Production rigor (full PRD/architecture/verify/refactor)
 * when the spec serves real users, is maintained over time, OR touches sensitive
 * data; otherwise prototype rigor (skip the ceremony — a throwaway doesn't need a PRD).
 */
export function decideRigor(spec: Spec): Rigor {
  return spec.realUsers || spec.maintained || isSensitive(spec) ? "production" : "prototype";
}

const TENANCIES: readonly Tenancy[] = ["single-user", "single-tenant", "multi-tenant"];
const SENSITIVE: readonly SensitiveClass[] = ["none", "pii", "phi", "financial", "credentials"];
const DEPLOY_TARGETS: readonly DeployTarget[] = ["hosted-app", "downloadable-tool"];

const asStr = (v: unknown, d = ""): string => (typeof v === "string" ? v : d);
const asBool = (v: unknown, d = false): boolean => (typeof v === "boolean" ? v : d);
const asStrArr = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.trim().length > 0) : [];

function coerceEntity(v: unknown): DataEntity | null {
  if (!v || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  const name = asStr(o.name).trim();
  if (!name) return null; // an entity with no name is noise — drop it
  return { name, fields: asStrArr(o.fields), sensitive: asBool(o.sensitive) };
}

/** Force any parsed JSON into a valid `Spec`. Conservative defaults so a missing
 *  field never silently looks "safe" (e.g. omitted auth → "none", which a sensitive-data
 *  check then flags rather than assuming auth exists). */
export function coerceSpec(raw: unknown): Spec {
  const o = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const tenancy = TENANCIES.includes(o.tenancy as Tenancy) ? (o.tenancy as Tenancy) : "single-user";
  // Unknown/missing → "hosted-app": the stricter verify path (boot-and-health-check is a
  // strictly more demanding bar than a CLI run), so failing toward it is the safe direction.
  const deployTarget = DEPLOY_TARGETS.includes(o.deployTarget as DeployTarget) ? (o.deployTarget as DeployTarget) : "hosted-app";
  const sensitiveData = (Array.isArray(o.sensitiveData) ? o.sensitiveData : []).filter(
    (x): x is SensitiveClass => SENSITIVE.includes(x as SensitiveClass),
  );
  const dataEntities = (Array.isArray(o.dataEntities) ? o.dataEntities : [])
    .map(coerceEntity)
    .filter((e): e is DataEntity => e !== null);
  return {
    name: asStr(o.name, "untitled-app").trim() || "untitled-app",
    summary: asStr(o.summary),
    features: asStrArr(o.features),
    users: asStr(o.users),
    tenancy,
    deployTarget,
    auth: asStr(o.auth, "none").trim() || "none",
    storesData: asBool(o.storesData, dataEntities.length > 0),
    dataEntities,
    sensitiveData: sensitiveData.length ? [...new Set(sensitiveData)] : ["none"],
    realUsers: asBool(o.realUsers),
    maintained: asBool(o.maintained),
  };
}
