/**
 * verify gate — cli path, end to end (PROJECT_BRIEF.md §12, deploy-target follow-up). Proves a
 * `deployTarget: "downloadable-tool"` app is verified by running its entry point ONCE to
 * completion (not by launching + probing a port) — fixing the real dogfooding failure where
 * `verify` demanded a bootable HTTP server from a local CLI/TUI tool.
 *
 * Spawns a real `node` process (fast, no network, no port), so — matching this file's sibling
 * verify.build.integration.test.ts, which gates even a dependency-free `npm run build` the same
 * way — this stays behind VIBEHARD_INTEGRATION rather than the default fast suite.
 *
 *   VIBEHARD_INTEGRATION=1 bun test verify.cli.integration
 */
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runVerify } from "./verify.ts";

const tmps: string[] = [];
afterEach(async () => {
  for (const d of tmps.splice(0)) await rm(d, { recursive: true, force: true });
});
async function scratch(files: Record<string, string>): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "vibehard-cli-verify-"));
  tmps.push(d);
  for (const [path, content] of Object.entries(files)) await Bun.write(join(d, path), content);
  return d;
}

const run = process.env.VIBEHARD_INTEGRATION ? describe : describe.skip;

run("verify cli path (real node spawn, downloadable-tool deployTarget)", () => {
  test("a CLI entry that runs to completion and exits 0 → verify PASS (exiting IS success here, unlike a server)", async () => {
    const dir = await scratch({
      "cli.js": "console.log('did the thing'); process.exit(0);",
      "package.json": '{"main":"cli.js"}',
      ".vibehard/spec.json": JSON.stringify({ deployTarget: "downloadable-tool" }),
    });
    const v = await runVerify(dir);
    expect(v.status).toBe("pass");
    expect(v.findings).toEqual([]);
  }, 30_000);

  test("a CLI entry that exits non-zero → verify BLOCK (cli-run-failed, high, carries the error tail)", async () => {
    const dir = await scratch({
      "cli.js": "console.error('boom: something broke'); process.exit(1);",
      "package.json": '{"main":"cli.js"}',
      ".vibehard/spec.json": JSON.stringify({ deployTarget: "downloadable-tool" }),
    });
    const v = await runVerify(dir);
    expect(v.status).toBe("block");
    expect(v.findings).toHaveLength(1);
    expect(v.findings[0]).toMatchObject({ tool: "verify", ruleId: "cli-run-failed", severity: "high" });
    expect(v.findings[0]!.message).toContain("boom: something broke");
  }, 30_000);

  test("a hosted-app deployTarget with the same entry is unaffected (still the node/health-probe path)", async () => {
    // Byte-for-byte unchanged behavior for hosted-app: a script that exits immediately (no server)
    // fails the EXISTING health-check-failed path, not the new cli path — proving the "cli" kind
    // is strictly opt-in behind deployTarget, never silently applied to a hosted-app build.
    //
    // No sandbox deps injected (the default `runVerify(dir)` call below), so the EPIC #32
    // sandboxed-deploy branch (gated on deps.flyHost && deps.runSandbox both being present,
    // 2026-07-10 seam refactor) can never trigger here regardless of environment — unlike the
    // old FLY_API_TOKEN-driven auto-construction this package no longer does.
    const dir = await scratch({
      "server.js": "process.exit(0);",
      "package.json": '{"main":"server.js"}',
      ".vibehard/spec.json": JSON.stringify({ deployTarget: "hosted-app" }),
    });
    const v = await runVerify(dir);
    expect(v.status).toBe("block");
    expect(v.findings.some((f) => f.ruleId === "health-check-failed")).toBe(true);
    expect(v.findings.some((f) => f.ruleId === "cli-run-failed")).toBe(false);
  }, 30_000);
});
