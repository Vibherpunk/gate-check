/**
 * Scan-scope regression (PROJECT_BRIEF.md §11) with REAL semgrep + gitleaks.
 * Proves the false-positive bug from the dogfood run is fixed: findings planted in
 * a derived/build dir (.next/) are ignored, while authored source is still scanned,
 * and an all-derived project trips scan-failed (fail-closed). Guarded behind
 * VIBEHARD_INTEGRATION (needs `semgrep` + `gitleaks` on PATH — native binaries as of
 * 2026-07-06, not Docker; see SEMGREP_VERSION/GITLEAKS_VERSION in sast.ts/secrets.ts).
 *
 *   VIBEHARD_INTEGRATION=1 bun test scan-scope.integration
 */
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSast } from "./sast.ts";
import { runSecrets } from "./secrets.ts";

const tmps: string[] = [];
afterEach(async () => {
  for (const d of tmps.splice(0)) await rm(d, { recursive: true, force: true });
});
async function scratch(files: Record<string, string>): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "vibehard-scope-it-"));
  tmps.push(d);
  for (const [path, content] of Object.entries(files)) await Bun.write(join(d, path), content);
  return d;
}

// The exact things that false-flagged in the dogfood run, planted in .next/.
const PLANTED = `const STRIPE_SECRET_KEY = "sk_live_FAKEKEY_REPLACED_BEFORE_PUSH_00000000000000000";\nconst q = db.prepare(\`SELECT * FROM users WHERE name = '\${name}'\`);\n`;
const CLEAN_SERVER = `const { createServer } = require("node:http");\ncreateServer((_, r) => r.end("ok")).listen(process.env.PORT || 3000);\n`;

const run = process.env.VIBEHARD_INTEGRATION ? describe : describe.skip;

run("scan scope — gates inspect source, not derived output", () => {
  test("findings inside .next/ are IGNORED while clean source still PASSES", async () => {
    const dir = await scratch({ "server.js": CLEAN_SERVER, ".next/server/app/page.js": PLANTED });
    expect((await runSast(dir)).status).toBe("pass"); // the .next SQLi/secret are excluded
    expect((await runSecrets(dir)).status).toBe("pass");
  }, 120_000);

  test("the SAME findings in AUTHORED source still BLOCK (source is really scanned)", async () => {
    const dir = await scratch({ "server.js": PLANTED });
    expect((await runSast(dir)).status).toBe("block"); // SQLi + stripe key in source
    expect((await runSecrets(dir)).status).toBe("block");
  }, 120_000);

  test("an all-derived project trips scan-failed, not PASS (§11 fail-closed)", async () => {
    const dir = await scratch({ ".next/server/app/page.js": PLANTED }); // no authored source at all
    const sast = await runSast(dir);
    expect(sast.status).toBe("block");
    expect(sast.findings[0]).toMatchObject({ ruleId: "scan-failed", severity: "critical" });
    const secrets = await runSecrets(dir);
    expect(secrets.findings[0]).toMatchObject({ ruleId: "scan-failed", severity: "critical" });
  }, 120_000);

  // Found live 2026-07-07 on a real customer build: production tenant workspaces live at
  // ~/.vibehard/tenants/<id>/apps/<app> — nested inside a directory literally named .vibehard
  // (the platform's own state root, unrelated to the DERIVED_DIRS exclusion of a workspace's
  // OWN .vibehard/ subdir). Passing that ABSOLUTE path to semgrep with `--exclude .vibehard`
  // matched the ANCESTOR directory too (gitignore-style: a bare name excludes at any depth)
  // and excluded the entire target — "SAST scanned 0 files", failing closed, blocking two
  // real builds on nothing. Fixed by scanning "." with cwd set to the workspace, so no
  // ancestor segment is ever visible to the exclude matcher.
  test("a workspace nested under a .vibehard-named ancestor dir is still scanned (not excluded)", async () => {
    const root = await mkdtemp(join(tmpdir(), "vibehard-ancestor-it-"));
    tmps.push(root);
    const nested = join(root, ".vibehard", "tenants", "t1", "apps", "app1");
    await Bun.write(join(nested, "server.js"), PLANTED);
    const sast = await runSast(nested);
    expect(sast.status).toBe("block"); // real SQLi/secret found — proves it actually scanned
    expect(sast.findings.length).toBeGreaterThan(0);
    expect(sast.findings.some((f) => f.ruleId === "scan-failed")).toBe(false); // not a fail-closed no-scan
  }, 120_000);
});
