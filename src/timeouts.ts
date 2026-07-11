/**
 * Shared subprocess timeout for network-dependent or potentially-slow operations (npm/pip
 * install, a security scanner pass) that `Bun.spawnSync` does NOT bound by default — an
 * unbounded spawn can hang forever with zero crash trace, zero log output, and nothing
 * upstream (the fix loop, the web server's build stream, a human watching) ever finding out.
 *
 * Found live, 2026-07-09: a real dogfooding build went silent for ~7 hours with no error.
 * Every LLM call was already bounded (generateTextResilient, 240s + retry), so the most
 * likely cause, once that was ruled out, was exactly this: an unbounded npm install or
 * scanner call hanging on a stalled network connection.
 *
 * 5 minutes is generous for a routine install/scan and still finite. A genuinely heavier
 * one-shot operation (a from-scratch clean-env build) uses its own longer, explicit budget
 * (CLEAN_TIMEOUT_MS in verify.ts) — this constant is for the routine, per-round subprocess
 * calls that run on every gate pass / every fix-loop attempt.
 */
export const SUBPROCESS_TIMEOUT_MS = 300_000;
