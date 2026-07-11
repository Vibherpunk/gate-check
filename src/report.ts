/**
 * The gate-verdict printer — shared by `vibehard gate`/`vibehard deploy` (VibeHard's CLI) and this
 * package's own standalone `gate-check` CLI (`bin/gate-check.ts`), so there is exactly one
 * implementation of "print a pipeline result" instead of two that drift.
 *
 * `formatFinding` is an injection seam (same DI pattern as verify.ts's sandbox / completeness.ts's
 * reviewer): the default is a plain, technical one-liner. A host application with its own
 * plain-English translation layer (e.g. VibeHard's `translateFinding`, which reads from a curated,
 * product-specific dictionary — not portable, not this package's concern) injects its own formatter
 * to keep its existing richer CLI output unchanged.
 */
import type { Finding, GateVerdict } from "./types.ts";

/** Structurally matches both `PipelineResult` and `DeployResult` (`index.ts`) — duck-typed here,
 *  not imported, to avoid a circular import (index.ts already imports this module). */
export interface ReportResult {
  verdicts: GateVerdict[];
  passed: boolean;
  /** present only on a DeployResult; printed when present. */
  sentinel?: string | null;
}

const SEV_DOT: Record<Finding["severity"], string> = { critical: "🔴", high: "🔴", medium: "🟠", low: "🟡" };

function defaultFormatFinding(f: Finding, indent: string): void {
  console.log(`${indent}${SEV_DOT[f.severity]} ${f.tool}:${f.ruleId} @ ${f.file}:${f.line ?? "?"}`);
  console.log(`${indent}   ${f.message}`);
}

export interface PrintReportOptions {
  /** Format one finding for display; default prints tool:ruleId@file:line + the raw message. */
  formatFinding?: (f: Finding, indent: string) => void;
}

/** Print every gate's verdict, then the overall PASS/BLOCK line (+ sentinel status when the
 *  result carries one — i.e. a DeployResult). Pure side-effect (console.log); does not exit. */
export function printReport(result: ReportResult, opts: PrintReportOptions = {}): void {
  const formatFinding = opts.formatFinding ?? defaultFormatFinding;
  for (const v of result.verdicts) {
    console.log(`\n── ${v.gate} → ${v.status.toUpperCase()} (${v.blocking} blocking) ──`);
    for (const f of v.findings) formatFinding(f, "  ");
  }
  if (result.passed) {
    console.log("\n✅ PASS — deploy allowed");
    if ("sentinel" in result) console.log(`   sentinel written: ${result.sentinel}`);
  } else {
    console.log("\n🛑 BLOCK — deploy refused");
    if ("sentinel" in result) console.log("   no sentinel written");
  }
}
