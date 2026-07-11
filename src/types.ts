/**
 * Core types — the typed contract the gate chain speaks. Deterministic gates produce these;
 * an engine/LLM layer only ever fills inputs, never these verdicts (PROJECT_BRIEF.md §11-12).
 */

export type Severity = "critical" | "high" | "medium" | "low";

/** One concrete problem found by a scanner or static check. Structured on purpose —
 *  the escalation packet and the UI need the detail, never a flattened string. */
export interface Finding {
  tool: string; // "semgrep" | "gitleaks" | "rls" | "verify"
  ruleId: string;
  severity: Severity;
  file: string;
  line?: number;
  message: string;
}

/** A gate's deterministic verdict. `escalate` is reserved for the human layer. */
export interface GateVerdict {
  gate: string;
  /** "n/a" = the gate had nothing to check (e.g. no spec to classify, no data model to prove RLS on).
   *  Distinct from "pass" on PURPOSE — a vacuous pass must not read as "verified" (audit H4). It does
   *  not block a deploy, but it does not count as a verified pass either. */
  status: "pass" | "block" | "escalate" | "n/a";
  findings: Finding[];
  blocking: number; // count of findings that force a block
  ranAt: string; // ISO timestamp, stamped by the caller
}

/** A deterministic gate: code in (a project dir), verdict out. Engine-agnostic. */
export interface Gate {
  name: string;
  run(projectPath: string): Promise<GateVerdict>;
}

/** A finding is blocking if it's high/critical severity (or any leaked secret). */
export function isBlocking(f: Finding): boolean {
  return f.severity === "critical" || f.severity === "high" || f.tool === "gitleaks";
}

/** Roll a gate's findings into a verdict. Pure — unit-testable. */
export function verdictOf(gate: string, findings: Finding[], ranAt: string): GateVerdict {
  const blocking = findings.filter(isBlocking).length;
  return { gate, status: blocking > 0 ? "block" : "pass", findings, blocking, ranAt };
}

/** A gate with NOTHING to check (not "verified OK" — there was simply nothing applicable). Use this
 *  instead of an empty `verdictOf` so a no-op never masquerades as a real pass (audit H4 / B3). */
export function notApplicable(gate: string, ranAt: string): GateVerdict {
  return { gate, status: "n/a", findings: [], blocking: 0, ranAt };
}
