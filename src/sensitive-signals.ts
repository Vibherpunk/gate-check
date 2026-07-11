/**
 * Sensitive-signal detector (SECURITY_AUDIT_4 D-1). The compliance/pii gates are
 * classification-driven: the spec (.vibehard/spec.json) declares whether the app handles
 * sensitive data, and a "none" declaration used to switch both gates off UNCONDITIONALLY —
 * whoever wrote the spec fully controlled whether §21's assessment ever ran. That made the
 * classification self-certified: the party being graded supplied the fact being graded.
 *
 * This module makes the claim FALSIFIABLE. It scans the app's actual data model (SQL
 * migration column names) and authored source (field identifiers) for sensitive-data-SHAPED
 * signals, independent of anything the spec says. The gates call it on their would-be-N/A
 * path: declaration says "none" + scan agrees → fast N/A preserved; scan disagrees → the
 * gate runs anyway and surfaces a blocking classification-mismatch for a human to resolve.
 *
 * The token lists are deliberately HIGH-SIGNAL: `ssn`, `diagnosis`, `credit_card` say
 * "this stores real personal records." Common-in-every-app identifiers (`email`, `phone`,
 * `name` — present in any login form) are deliberately EXCLUDED so a genuinely
 * non-sensitive app keeps its fast N/A and this never becomes a false-block generator.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "./types.ts";
import type { SensitiveClass } from "./spec-contract.ts";
import { DERIVED_DIRS } from "./scan-scope.ts";

const DERIVED = new Set<string>(DERIVED_DIRS);

// Per-class identifier patterns. Dots tolerate snake/kebab/camel boundaries ("date.?of.?birth"
// matches date_of_birth, dateOfBirth, date-of-birth). Word-ish boundaries via lookarounds so
// `dob` doesn't fire inside "adobe".
const CLASS_PATTERNS: ReadonlyArray<[SensitiveClass, RegExp]> = [
  ["pii", /(?<![a-z0-9])(?:ssn|social.?security|date.?of.?birth|birth.?date|passport.?(?:number|no)|driver.?s?.?licen[sc]e|national.?id|tax.?id(?:entifier)?)(?![a-z0-9])/i],
  ["phi", /(?<![a-z0-9])(?:diagnosis|diagnoses|prescription|medical.?(?:record|history)|health.?record|patient.?(?:id|record|name|chart)|treatment.?plan|therapy.?note|blood.?type|medication)(?![a-z0-9])/i],
  ["financial", /(?<![a-z0-9])(?:credit.?card|card.?number|cvv|cvc|iban|routing.?number|bank.?account|account.?balance|net.?worth|salary)(?![a-z0-9])/i],
  ["credentials", /(?<![a-z0-9])(?:password.?hash|encrypted.?password|private.?key|secret.?key|access.?token|refresh.?token)(?![a-z0-9])/i],
];

export interface SensitiveSignal {
  class: SensitiveClass;
  evidence: string; // "file:line — matched `token`"
}

function walk(root: string, exts: string[]): Array<{ rel: string; code: string }> {
  const out: Array<{ rel: string; code: string }> = [];
  const rec = (dir: string, prefix: string): void => {
    try {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) {
          if (!DERIVED.has(e.name) && e.name !== ".vibehard") rec(join(dir, e.name), `${prefix}${e.name}/`);
        } else if (exts.some((x) => e.name.endsWith(x))) {
          try {
            const code = readFileSync(join(dir, e.name), "utf8");
            if (code.length < 300_000) out.push({ rel: `${prefix}${e.name}`, code });
          } catch {
            /* skip unreadable file */
          }
        }
      }
    } catch {
      /* unreadable dir → skip */
    }
  };
  rec(root, "");
  return out;
}

/**
 * Scan the app's SQL migrations + authored source for sensitive-data-shaped identifiers,
 * REGARDLESS of what the spec claims. Returns one entry per (class, site), capped, deduped
 * enough to be readable in a finding. Empty result = the code corroborates a "none" claim.
 */
export function detectSensitiveSignals(projectPath: string): SensitiveSignal[] {
  const out: SensitiveSignal[] = [];
  const seen = new Set<string>(); // one evidence line per class+file (avoid 40 hits in one schema)
  for (const { rel, code } of walk(projectPath, [".sql", ".ts", ".tsx", ".js", ".jsx", ".py"])) {
    const lines = code.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i]!;
      if (ln.trimStart().startsWith("--") || ln.trimStart().startsWith("//")) continue; // comments aren't a data model
      for (const [cls, re] of CLASS_PATTERNS) {
        const m = re.exec(ln);
        if (!m) continue;
        const key = `${cls}:${rel}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ class: cls, evidence: `${rel}:${i + 1} — \`${m[0]}\`` });
        if (out.length >= 12) return out;
      }
    }
  }
  return out;
}

/** The distinct classes present in a signal set — what the gate should assess when the spec denies. */
export function inferredClasses(signals: SensitiveSignal[]): SensitiveClass[] {
  return [...new Set(signals.map((s) => s.class))];
}

/** The blocking finding for a spec whose "nothing sensitive here" claim the code contradicts.
 *  High severity — a human must resolve it (fix the classification, or remove the fields);
 *  the gate must not silently trust either side. Shared by compliance + pii. */
export function classificationMismatch(tool: string, signals: SensitiveSignal[]): Finding {
  const classes = inferredClasses(signals).join(", ");
  const evidence = signals.slice(0, 6).map((s) => s.evidence).join("; ");
  return {
    tool,
    ruleId: "classification-mismatch",
    severity: "high",
    file: "classification",
    message:
      `The spec declares no sensitive data, but the code appears to handle ${classes} (${evidence}). ` +
      `A self-declared classification can't switch these checks off when the code contradicts it — ` +
      `either correct the classification in the spec, or remove the sensitive fields. Assessed as ${classes} in the meantime.`,
  };
}
