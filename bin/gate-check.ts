#!/usr/bin/env bun
/**
 * Standalone gate-check CLI — runs the same deterministic gate chain as `vibehard gate`/
 * `vibehard deploy`, against any codebase, with zero VibeHard dependency. No sandbox and no LLM
 * reviewer are wired in (this package has no default for either — see verify.ts/completeness.ts),
 * so `verify` falls back to the local docker/npm path and `completeness` reports a blocking
 * "not configured" finding whenever a spec with real features is present; every other gate runs
 * exactly as it would inside VibeHard.
 *
 * usage: gate-check [gate|deploy] <dir>   (defaults to "gate" when the subcommand is omitted)
 */
import { runGate, deployGate, printReport } from "../src/index.ts";

async function main(argv: string[]): Promise<number> {
  const [first, second] = argv;
  const cmd = first === "gate" || first === "deploy" ? first : "gate";
  const dir = first === "gate" || first === "deploy" ? second : first;

  if (!dir) {
    console.error("usage: gate-check [gate|deploy] <dir>");
    return 2;
  }

  const result = cmd === "deploy" ? await deployGate(dir) : await runGate(dir);
  printReport(result);
  return result.passed ? 0 : 1;
}

if (import.meta.main) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
