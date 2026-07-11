/**
 * verify gate — build path, end to end (PROJECT_BRIEF.md §12). Proves a static/SPA
 * app is verified by building it (not by probing a server), so a legit Vite-style
 * app is no longer false-blocked as "no entry point", and a broken build is caught.
 *
 * Runs `npm run build`, so guarded behind VIBEHARD_INTEGRATION. Fixtures declare NO
 * dependencies, so no `npm install` / network is needed — the real-deps (Vite)
 * install+build path is exercised by live generation (needs ANTHROPIC_API_KEY).
 *
 *   VIBEHARD_INTEGRATION=1 bun test verify.build.integration
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
async function scratch(pkg: object): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "vibehard-build-"));
  tmps.push(d);
  await Bun.write(join(d, "package.json"), JSON.stringify(pkg));
  return d;
}

const run = process.env.VIBEHARD_INTEGRATION ? describe : describe.skip;

run("verify build path (real npm run build)", () => {
  test("a passing build → verify PASS", async () => {
    const dir = await scratch({
      name: "spa",
      private: true,
      scripts: { build: "node -e \"require('fs').mkdirSync('dist',{recursive:true});require('fs').writeFileSync('dist/index.html','ok')\"" },
    });
    const v = await runVerify(dir);
    expect(v.status).toBe("pass");
    expect(await Bun.file(join(dir, "dist/index.html")).exists()).toBe(true);
  }, 60_000);

  test("a failing build → verify BLOCK (build-failed)", async () => {
    const dir = await scratch({ name: "broken", private: true, scripts: { build: "exit 1" } });
    const v = await runVerify(dir);
    expect(v.status).toBe("block");
    expect(v.findings[0]).toMatchObject({ tool: "verify", ruleId: "build-failed" });
  }, 60_000);
});
