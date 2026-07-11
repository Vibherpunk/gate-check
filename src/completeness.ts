/**
 * The COMPLETENESS gate (backlog §18 verify-contract): does the app actually implement the
 * features the user asked for? The other gates prove it BUILDS and is SAFE — none proves it's
 * DONE. A secure app that ships 1 of 10 promised features passes all of them; this is the gate
 * that makes "passes" mean "complete", not just "compiles safely".
 *
 * It reuses the functional reviewer (an LLM reads the spec's features vs the code, per-feature)
 * but, unlike the advisory `functest`, it BLOCKS on a feature that is entirely MISSING — and the
 * finding is actionable, so the auto-fix loop's next pass GENERATES the missing feature (wired to
 * the schema, which planning already produced). Only `missing` blocks (the clearest signal); a
 * `partial` feature is surfaced but doesn't block (an LLM's "partial" judgment is too subjective
 * to gate a deploy on). No spec / no features → not applicable, no block. A reviewer that THROWS
 * (model outage, exhausted credits) fails CLOSED with a blocking `completeness-unverified`
 * finding — an unverifiable app must not ship on silence (SECURITY_AUDIT_4 doc fix: this
 * docstring previously claimed the opposite of what the catch block does).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Glob } from "bun";
import type { Finding, Gate, GateVerdict } from "./types.ts";
import { notApplicable, verdictOf } from "./types.ts";
import type { FunctionalReviewer } from "./functest.ts";

// Feature-name words that carry no signal about WHICH feature it is — they appear in many features,
// so a match on them would let a genuinely-missing feature slip through. Distinctiveness comes from
// the domain noun (immunization, billing, attendance, …), not these.
const FEATURE_STOPWORDS = new Set([
  "and", "the", "for", "with", "management", "managing", "tracking", "track", "system", "records",
  "record", "page", "pages", "feature", "features", "support", "processing", "sharing", "scheduling",
  "schedule", "details", "detail", "data", "info", "information", "user", "users", "app",
]);

/** Deterministic guard against the reviewer's false negatives: does a feature the LLM called
 *  "missing" actually have a plausibly-matching implementation on disk? The grader is noisiest on
 *  features WITHOUT a dedicated route — "payment processing" lives inside billing, "role-based
 *  access control" in middleware/lib — so it intermittently calls them missing. But a feature's
 *  DISTINCTIVE domain word(s) (payment, immunization, staff…; generic words like "management"/
 *  "tracking"/"records" are stopworded) show up in the code that implements it — in a file PATH
 *  (a route/module named for it) or, for a folded-in feature, in file CONTENT. If a distinctive
 *  token appears either place, the feature is present (≠ entirely missing, which is all this gate
 *  blocks on). A truly-absent feature has its domain term nowhere in the code → still blocks. */
/** A file shows REAL behavior (not a named stub): it has an implementation signal (a DB call, an async
 *  handler, a form, hooks, JSX elements, a route export) AND a non-trivial body. This is what stops a
 *  fixer from clearing a "missing" finding by dropping an empty file named for the feature (audit B2). */
const IMPL_SIGNAL = /\bawait\b|\buseState\b|\buseEffect\b|onSubmit|<form|fetch\(|\.from\(|createClient|server-only|use server|export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)|<[A-Z][A-Za-z0-9]/;
function substantive(code: string): boolean {
  // Strip comments AND string/template literals before measuring (audit3 M-3): a stub padded with a
  // long string literal (`const _pad = "billing billing billing…"`) used to inflate the length past 200
  // and vindicate. We also test the impl signal on the STRIPPED code so an `await`/`<form` hidden in a
  // string or comment can't count as real behavior.
  const stripped = code
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/`(?:\\.|[^`\\])*`/g, "``") // template literals → empty
    .replace(/"(?:\\.|[^"\\])*"/g, '""') // double-quoted → empty
    .replace(/'(?:\\.|[^'\\])*'/g, "''") // single-quoted → empty
    .replace(/\s+/g, " ")
    .trim();
  return stripped.length >= 200 && IMPL_SIGNAL.test(stripped); // real logic + real size, not a padded stub
}

export function looksImplemented(feature: string, projectPath: string): boolean {
  const tokens = (feature.toLowerCase().match(/[a-z]{5,}/g) ?? []).filter((t) => !FEATURE_STOPWORDS.has(t));
  if (!tokens.length) return false; // no distinctive token to match on → can't vindicate; trust the LLM
  let budget = 600_000; // bound the content scan (≈ the reviewer's own source cap)
  for (const sub of ["app", "lib", "components"]) {
    const root = join(projectPath, sub);
    if (!existsSync(root)) continue;
    for (const rel of new Glob("**/*.{ts,tsx,js,jsx,sql}").scanSync({ cwd: root, dot: false })) {
      if (budget <= 0) break;
      let code: string;
      try {
        code = readFileSync(join(root, rel), "utf8");
      } catch {
        continue; // unreadable → skip
      }
      budget -= code.length;
      const matched = tokens.some((t) => rel.toLowerCase().includes(t)) || tokens.some((t) => code.toLowerCase().includes(t));
      // A token match ONLY vindicates if the matching file actually IMPLEMENTS something — a file
      // merely named for the feature, or one that just mentions the word, is not "present".
      if (matched && substantive(code)) return true;
    }
  }
  return false;
}

export interface CompletenessOptions {
  // No package-owned default (2026-07-10 seam decoupling): the host application must inject a
  // configured reviewer (e.g. VibeHard's own `llmFunctionalReviewer({modelFactory, config})`) to
  // actually run this check. Not injected → treated the SAME as a reviewer that throws (below):
  // fails CLOSED, not silently n/a — a spec with real features genuinely wants this checked, and
  // "no reviewer wired" is exactly as "unverifiable" as "the wired reviewer broke."
  reviewer?: FunctionalReviewer;
  ranAt?: string;
}

export async function runCompleteness(projectPath: string, opts: CompletenessOptions = {}): Promise<GateVerdict> {
  const ranAt = opts.ranAt ?? new Date().toISOString();
  const specPath = join(projectPath, ".vibehard", "spec.json");
  if (!existsSync(specPath)) return notApplicable("completeness", ranAt); // didn't go through planning → N/A

  let features: string[] = [];
  try {
    const spec = JSON.parse(readFileSync(specPath, "utf8")) as { features?: string[] };
    features = (spec.features ?? []).map((f) => String(f).trim()).filter(Boolean);
  } catch {
    return notApplicable("completeness", ranAt);
  }
  if (!features.length) return notApplicable("completeness", ranAt);

  if (!opts.reviewer) {
    const message = `Could not verify feature completeness — no functional reviewer is configured. This is a setup problem, NOT a code change: the host application must supply a reviewer for this check to run. Failing closed so an unverifiable build is never called "done".`;
    return verdictOf("completeness", [{ tool: "completeness", ruleId: "completeness-unverified", severity: "high", file: "app/", message }], ranAt);
  }
  const reviewer = opts.reviewer;
  let checks;
  try {
    checks = await reviewer(features, projectPath);
  } catch (e) {
    // The reviewer was asked to judge real features but produced nothing usable (model outage, or
    // a reasoning model that emitted no JSON even after retry). For a CORRECTNESS gate, "couldn't
    // verify" must NOT pass — that's how a build silently ships incomplete. Fail CLOSED with a
    // DISTINCT ruleId so the auto-fix loop treats this as an infra retry/hold, not a feature to
    // build (there's no missing feature to generate here — the judgment itself failed).
    const message = `Could not verify feature completeness — the functional reviewer returned no usable result (${e instanceof Error ? e.message : String(e)}). This is a reviewer/infra problem, NOT a code change: re-run the gate; if it persists a human must check the reviewer model/credentials before this build is declared complete. Failing closed so an unverifiable build is never called "done".`;
    return verdictOf("completeness", [{ tool: "completeness", ruleId: "completeness-unverified", severity: "high", file: "app/", message }], ranAt);
  }
  if (!checks.length) return notApplicable("completeness", ranAt); // genuine N/A (no app sources to read) → don't block

  // Only an entirely-MISSING feature blocks — but guard the reviewer's FALSE NEGATIVES: the LLM's
  // "missing" verdict varies on a nested/borderline feature (observed: "immunization & health
  // records" was implemented under children/[id]/health-records + lib/health-records.ts, yet graded
  // "missing" on one run and "present" the next — which kept a genuinely-complete app from
  // converging). File/route existence is DETERMINISTIC, so if a feature the LLM called "missing"
  // actually has a plausibly-matching implementation on disk, it is NOT missing (at most partial,
  // which doesn't block). A truly-absent feature matches nothing → still blocks.
  const findings: Finding[] = checks
    .filter((c) => c.status === "missing" && !looksImplemented(c.feature, projectPath))
    .map((c) => ({
      tool: "completeness",
      ruleId: "feature-missing",
      severity: "high",
      file: "app/",
      message: `The app is missing a feature the user explicitly asked for: "${c.feature}". ${c.note} BUILD it now — create the page(s)/UI and the server actions for it, wired to the database tables planning already created for it (check supabase/migrations and lib/ for the matching table/types). A build that silently drops a promised feature is NOT done.`,
    }));
  return verdictOf("completeness", findings, ranAt);
}

// Bare default: no reviewer injected, so any spec with real features fails closed (see above) —
// genuinely standalone use (no LLM configured at all) still gets an honest, non-silent verdict.
export const completenessGate: Gate = { name: "completeness", run: (p: string) => runCompleteness(p) };

/** Construct a completeness gate bound to a specific reviewer — what a host application (e.g.
 *  VibeHard's own gate-wiring layer, passing `llmFunctionalReviewer({modelFactory, config})`)
 *  uses in place of the bare `completenessGate` to actually run the check for real. */
export function createCompletenessGate(opts: CompletenessOptions): Gate {
  return { name: "completeness", run: (p: string) => runCompleteness(p, opts) };
}
