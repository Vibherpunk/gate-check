/**
 * VENDORED (2026-07-10 extraction) from VibeHard's `src/proptest/validate.ts` — the property-test
 * GENERATOR (`src/proptest/generate.ts`, LLM-driven, VibeHard-specific) stays in VibeHard; this
 * package only needs the pure vacuity predicates the `proptest` gate disposes with, reused at
 * generation time by VibeHard's own generator too. Kept as an independent copy, not a re-export
 * shim: this logic is small, has zero dependencies, and is shared BETWEEN two owners rather than
 * owned by gate-check outright.
 *
 * Property-test vacuity guards (EPIC #53). A generated property test earns its place in the
 * gate line only if it demonstrably tests something: imports fast-check, asserts at least one
 * property, imports the app module under test, runs DETERMINISTICALLY (fixed seed — a flaky
 * gate is worse than no gate), and isn't skipped. All checks are pure string predicates —
 * no LLM judgment anywhere in the dispose path (§11).
 *
 * These run at two moments, same function both times:
 *   • generation time — an invalid file is regenerated or dropped, never written silently;
 *   • gate time — an invalid file that EXISTS is a BLOCKING finding, because the only way a
 *     valid file becomes invalid is someone (the fixer) trying to neuter it. That plus the
 *     anti-tamper hash check makes "weaken the test instead of fixing the app" a dead end.
 */

export const PROPTEST_DIR = "tests/properties";

/** One requirement → one test file: tests/properties/<safe-id>.test.ts. */
export function propTestFileName(requirementId: string): string {
  const safe = requirementId.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return `${safe || "req"}.test.ts`;
}

/** The requirement a test file covers, from its `// @requirement <id>` header. */
export function requirementIdOf(content: string): string | null {
  return /^\/\/ @requirement\s+([A-Za-z0-9._-]+)/m.exec(content)?.[1] ?? null;
}

/** Why this test file content is vacuous/invalid, or null if it's a real property test. Pure. */
export function propTestVacuityReason(content: string): string | null {
  if (!/^\/\/ @requirement\s+\S+/m.test(content)) return "missing the `// @requirement <id>` header linking it to a requirement";
  if (!/from\s+["']fast-check["']|require\(\s*["']fast-check["']\s*\)/.test(content)) return "does not import fast-check";
  if (!/\bfc\.assert\s*\(/.test(content)) return "contains no fc.assert() — asserts no property";
  if (!/from\s+["'](?:\.\.?\/|@\/)/.test(content)) return "imports no app module (nothing under test)";
  if (!/\bseed\s*:\s*\d+/.test(content)) return "has no fixed seed (seed: <n>) — a randomly-seeded gate run is nondeterministic";
  if (/\.(?:skip|todo)\s*\(/.test(content)) return "contains .skip/.todo — a skipped property is an unchecked property";
  return null;
}
