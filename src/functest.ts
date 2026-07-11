/**
 * VENDORED (2026-07-10 extraction) from VibeHard's `src/functest/functest.ts`, with the same LLM
 * seam treatment as `@vibehard/orchestrator`'s `orchestrator-llm.ts`: `modelFactory`/`config` are
 * REQUIRED on `llmFunctionalReviewer(opts)`, not optional-with-a-VibeHard-flavored-default (which
 * model/provider to use by default is itself a piece of VibeHard's own roster, not something this
 * package should silently pick). `generateTextResilient`/`tryExtractJsonObject` are duplicated
 * rather than imported from VibeHard's `engine/bolt/driver.ts`/`spec/coerce.ts` — both are small,
 * VibeHard-logic-free, and this fully severs the package's dependency on VibeHard internals.
 *
 * Functional review (backlog #11). The verify gate proves an app BOOTS and answers HTTP; it does
 * not prove the app DOES what the user asked. This is the first half of "does it actually work":
 * an LLM QA tester inspects the generated code against the requirements and judges, per feature,
 * whether it's implemented end-to-end ("works"), started-but-incomplete ("partial"), or absent
 * ("missing").
 *
 * HONEST SCOPE: this is a code-level functional-COVERAGE check, not a runtime drive of the live
 * app. Advisory (never blocks): `coerceChecks` is the trust boundary; the LLM proposes, a human
 * disposes.
 */
import type { LanguageModel } from "ai";
import { generateText } from "ai";
import { readAppSources } from "./rls.ts";

/** Minimal, package-local model-selection contract — structurally compatible with VibeHard's own
 *  `EngineConfig` ({provider, model}), so the host application's config passes through unchanged. */
export interface LlmConfig {
  provider: string;
  model: string;
}
export type ModelFactory = (config: LlmConfig) => LanguageModel;

/** Duplicated from VibeHard's `engine/bolt/driver.ts` (same reasoning there: transient-fault
 *  resilience + provider-degeneration detection, zero VibeHard-specific logic). */
async function generateTextResilient(
  args: Parameters<typeof generateText>[0],
  opts: { retries?: number; timeoutMs?: number } = {},
): Promise<Awaited<ReturnType<typeof generateText>>> {
  const retries = opts.retries ?? 2;
  const timeoutMs = opts.timeoutMs ?? 240_000;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const result = await generateText({ ...args, abortSignal: AbortSignal.timeout(timeoutMs) });
      if (!result.text.trim()) {
        lastErr = new Error("whitespace-only model response");
        if (attempt === retries) throw lastErr;
        await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
        continue;
      }
      return result;
    } catch (e) {
      lastErr = e;
      const sig = e instanceof Error ? `${e.name} ${e.message}` : String(e);
      const transient = /timed out|timeout|ECONNRESET|fetch failed|network|terminated|socket|JSON parse|JSONParseError|JSON parsing failed|Invalid JSON response|Unexpected EOF|whitespace-only|\b(429|500|502|503|504)\b/i.test(sig);
      if (!transient || attempt === retries) throw e;
      console.error(`[llm-retry] attempt ${attempt + 1}/${retries + 1} failed transiently (${sig.slice(0, 120)}) — retrying`);
      await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
    }
  }
  throw lastErr;
}

/** Duplicated from VibeHard's `spec/coerce.ts` — pull the first JSON object out of LLM text
 *  (fenced, bare, or wrapped in prose). */
function tryExtractJsonObject(text: string): unknown | null {
  try {
    const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    const body = fence ? (fence[1] ?? "") : text;
    const start = body.indexOf("{");
    const end = body.lastIndexOf("}");
    if (start === -1 || end === -1 || end < start) return null;
    return JSON.parse(body.slice(start, end + 1));
  } catch {
    return null;
  }
}

/** Thrown when the reviewer was ASKED to judge real features over real sources but the model
 *  produced no usable output (empty/unparseable, even after a retry). Distinct from a legitimate
 *  N/A (no features / no sources → []), so a caller like the completeness gate can fail CLOSED
 *  on "couldn't verify" instead of mistaking it for "nothing to flag" (a false pass). */
export class FunctionalReviewUnavailable extends Error {}

export type CheckStatus = "works" | "partial" | "missing";

export interface FunctionalCheck {
  feature: string;
  status: CheckStatus;
  note: string; // why — what's present / what's stubbed or absent
}

const STATUSES: readonly CheckStatus[] = ["works", "partial", "missing"];

/** Trust boundary: coerce the model's JSON into valid, de-duplicated checks. */
export function coerceChecks(raw: unknown): FunctionalCheck[] {
  const o = raw && typeof raw === "object" ? (raw as { checks?: unknown }) : {};
  const arr = Array.isArray(o.checks) ? o.checks : Array.isArray(raw) ? (raw as unknown[]) : [];
  const out: FunctionalCheck[] = [];
  const seen = new Set<string>();
  for (const c of arr) {
    if (!c || typeof c !== "object") continue;
    const r = c as Record<string, unknown>;
    const feature = typeof r.feature === "string" ? r.feature.trim() : "";
    if (!feature || seen.has(feature)) continue;
    const status: CheckStatus = STATUSES.includes(r.status as CheckStatus) ? (r.status as CheckStatus) : "partial";
    const note = typeof r.note === "string" ? r.note.trim() : "";
    seen.add(feature);
    out.push({ feature, status, note });
    if (out.length >= 25) break;
  }
  return out;
}

/** Roll the checks into a one-line verdict for the operator/UI. */
export function summarize(checks: FunctionalCheck[]): { works: number; partial: number; missing: number; total: number } {
  return {
    works: checks.filter((c) => c.status === "works").length,
    partial: checks.filter((c) => c.status === "partial").length,
    missing: checks.filter((c) => c.status === "missing").length,
    total: checks.length,
  };
}

const FUNCTEST_SYSTEM_PROMPT = `You are a QA tester checking whether a generated web app actually IMPLEMENTS what the user asked for. For EACH feature/flow listed, inspect the code and decide:
- "works": implemented end-to-end (the UI exists AND it's wired to real data/logic that would plausibly function),
- "partial": started but incomplete or faked — e.g. a button with no handler, a form that doesn't persist, hardcoded/mock data, a TODO, a route that renders nothing useful,
- "missing": not implemented at all.

Be SKEPTICAL and concrete. A screen that renders but doesn't save or load real data is "partial", not "works". In each note, point to what made you decide (a file/handler that exists, or what's absent/stubbed).

Return ONLY JSON: { "checks": [ { "feature": string, "status": "works" | "partial" | "missing", "note": string } ] }`;

const SOURCE_CAP = 90_000;
function sourceBlock(sources: Array<{ file: string; code: string }>): string {
  const out: string[] = [];
  let total = 0;
  for (const { file, code } of sources) {
    if (total >= SOURCE_CAP) break;
    total += code.length;
    out.push(`--- ${file} ---\n${code}`);
  }
  return out.join("\n\n");
}

export interface FunctionalReviewer {
  (features: string[], workspace: string): Promise<FunctionalCheck[]>;
}

export interface FunctionalReviewOptions {
  modelFactory: ModelFactory;
  config: LlmConfig;
}

/** The live functional reviewer — one model call over the features + the app's code. */
export function llmFunctionalReviewer(opts: FunctionalReviewOptions): FunctionalReviewer {
  const { modelFactory, config } = opts;
  return async (features, workspace) => {
    const cleaned = features.map((f) => f.trim()).filter(Boolean);
    if (!cleaned.length) return []; // legitimate N/A — nothing to review
    const sources = await readAppSources(workspace);
    if (!sources.length) return []; // legitimate N/A — no app code to read
    const prompt = `Features the app must have:\n${cleaned.map((f) => `- ${f}`).join("\n")}\n\nThe app's code:\n\n${sourceBlock(sources)}`;
    // The light tier is a REASONING model — it spends output tokens THINKING before emitting the
    // JSON. At 4k that budget was eaten by reasoning → empty text → coerceChecks([]) → a caller
    // reading [] as "nothing missing" → FALSE PASS (observed: same source judged "7 missing" then
    // "all present" on consecutive runs). Give it real headroom, and retry once before giving up.
    let lastLen = 0;
    for (let attempt = 0; attempt < 2; attempt++) {
      let text = "";
      try {
        ({ text } = await generateTextResilient(
          {
            model: modelFactory(config),
            system: FUNCTEST_SYSTEM_PROMPT,
            prompt,
            maxOutputTokens: 16_000,
            temperature: 0, // judge the SAME code the same way every round — sampling variance made the
            // completeness verdict wobble (a feature flagged missing one round, present the next),
            // which stops a finished build from converging. Greedy decoding makes the grade stable.
          },
          { retries: 0 },
        ));
      } catch {
        text = ""; // an unusable response counts as a failed attempt of THIS loop
      }
      lastLen = (text ?? "").length;
      const checks = coerceChecks(tryExtractJsonObject(text ?? ""));
      if (checks.length) return checks;
    }
    // Asked to judge real features over real sources, got nothing usable twice → fail LOUD, not [].
    throw new FunctionalReviewUnavailable(`functional reviewer produced no usable checks for ${cleaned.length} feature(s) over ${sources.length} source file(s) (model=${config.model}; last response ${lastLen} chars)`);
  };
}
