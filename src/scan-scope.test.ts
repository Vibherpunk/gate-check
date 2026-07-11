import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVED_DIRS, hasAuthoredSource, relativizeFinding } from "./scan-scope.ts";

const tmps: string[] = [];
afterEach(async () => {
  for (const d of tmps.splice(0)) await rm(d, { recursive: true, force: true });
});
async function scratch(files: Record<string, string>): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "vibehard-scope-"));
  tmps.push(d);
  for (const [path, content] of Object.entries(files)) await Bun.write(join(d, path), content);
  return d;
}

describe("DERIVED_DIRS", () => {
  test("covers the full derived/build set (not just .next)", () => {
    const dirs: readonly string[] = DERIVED_DIRS;
    for (const d of ["node_modules", ".next", "dist", "build", "out", "coverage", ".turbo", ".git"]) {
      expect(dirs).toContain(d);
    }
  });
});

describe("hasAuthoredSource (§11 fail-closed guard)", () => {
  test("true when an authored source file exists (root or nested)", async () => {
    expect(hasAuthoredSource(await scratch({ "server.js": "x" }))).toBe(true);
    expect(hasAuthoredSource(await scratch({ "app/page.tsx": "x", "package.json": "{}" }))).toBe(true);
  });

  test("FALSE when only derived/build output is present (the exclusion-ate-everything case)", async () => {
    expect(hasAuthoredSource(await scratch({ ".next/server/app/page.js": "leaked", "node_modules/x/i.js": "y" }))).toBe(false);
  });

  test("false for an empty or missing dir", async () => {
    expect(hasAuthoredSource(await scratch({}))).toBe(false);
    expect(hasAuthoredSource(join(tmpdir(), "vibehard-does-not-exist-xyz"))).toBe(false);
  });

  test("authored source nested alongside derived dirs is still found", async () => {
    expect(hasAuthoredSource(await scratch({ "node_modules/x/i.js": "y", ".next/c.js": "z", "src/main.ts": "ok" }))).toBe(true);
  });
});

describe("relativizeFinding (2026-07-06 — native scanners report host-absolute paths)", () => {
  // Before this fix, a docker-wrapped scanner reported container-relative paths
  // (/src/server.js) that Finding.file stored VERBATIM — anti-tamper's `join(root, f.file)`
  // on those was already broken (it doesn't exist under root either), so sast/secrets
  // findings never populated `flaggedFiles`. Native invocation reports real host-absolute
  // paths; this normalizes them to the same root-relative convention every other gate uses.
  test("a file under root becomes root-relative", () => {
    expect(relativizeFinding("/app", "/app/lib/server.js")).toBe("lib/server.js");
    expect(relativizeFinding("/app", "/app/server.js")).toBe("server.js");
  });

  test("the root itself (a whole-project scan-failed finding) becomes '.'", () => {
    expect(relativizeFinding("/app", "/app")).toBe(".");
  });

  test("a path outside root is left absolute rather than mangled with '..'", () => {
    expect(relativizeFinding("/app", "/elsewhere/x.js")).toBe("/elsewhere/x.js");
  });

  test("an already-relative or empty path passes through unchanged", () => {
    expect(relativizeFinding("/app", "server.js")).toBe("server.js");
    expect(relativizeFinding("/app", "")).toBe("");
  });
});

describe("gitleaks.toml allowlist stays in sync with DERIVED_DIRS (2026-07-07 regression)", () => {
  // Found live on a real customer build: gitleaks.toml's hand-written allowlist was missing
  // .vibehard (present in DERIVED_DIRS) — gitleaks scanned .vibehard/owned.json (a file→sha256
  // bookkeeping map) and flagged a hex hash as a "Generic API Key", blocking the build on
  // nothing. TOML can't import the TS constant, so this test is the sync mechanism: drift
  // fails a test run, not a customer's gate.
  test("every DERIVED_DIRS entry appears in the gitleaks allowlist path regex", async () => {
    const toml = await readFile(join(import.meta.dir, "rules", "gitleaks.toml"), "utf8");
    for (const dir of DERIVED_DIRS) {
      const escaped = dir.replace(/\./g, "\\.");
      expect(toml).toContain(escaped);
    }
  });
});
