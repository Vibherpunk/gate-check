import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stampSentinel, verifySentinel, SENTINEL_REL } from "./index.ts";

async function tempDir(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "vibehard-sentinel-"));
  return d;
}

describe("stampSentinel / verifySentinel — CRITICAL-3: sentinel must be HMAC-authenticated", () => {
  test("stamp → verify round-trip passes", async () => {
    const dir = await tempDir();
    try {
      await stampSentinel(dir, true);
      expect(existsSync(join(dir, SENTINEL_REL))).toBe(true);
      expect(verifySentinel(dir)).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("a failed gate clears the sentinel (ratchet)", async () => {
    const dir = await tempDir();
    try {
      await stampSentinel(dir, true);
      expect(verifySentinel(dir)).toBe(true);
      await stampSentinel(dir, false); // gate failed → sentinel removed
      expect(existsSync(join(dir, SENTINEL_REL))).toBe(false);
      expect(verifySentinel(dir)).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("a manually created timestamp-only sentinel is rejected (forgery attempt)", async () => {
    const dir = await tempDir();
    try {
      const sentinelPath = join(dir, SENTINEL_REL);
      mkdirSync(join(dir, ".gate"), { recursive: true });
      writeFileSync(sentinelPath, `${new Date().toISOString()}\n`); // old format: no HMAC
      expect(verifySentinel(dir)).toBe(false); // missing MAC → denied
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("a sentinel copied from one project to another is rejected (path-bound HMAC)", async () => {
    const dir1 = await tempDir();
    const dir2 = await tempDir();
    try {
      await stampSentinel(dir1, true);
      // Copy the sentinel from dir1 into dir2's .gate/
      const content = require("node:fs").readFileSync(join(dir1, SENTINEL_REL), "utf8");
      mkdirSync(join(dir2, ".gate"), { recursive: true });
      writeFileSync(join(dir2, SENTINEL_REL), content);
      // dir1's sentinel is valid for dir1 but NOT for dir2
      expect(verifySentinel(dir1)).toBe(true);
      expect(verifySentinel(dir2)).toBe(false);
    } finally {
      await rm(dir1, { recursive: true, force: true });
      await rm(dir2, { recursive: true, force: true });
    }
  });

  test("no sentinel → verifySentinel returns false", async () => {
    const dir = await tempDir();
    try {
      expect(verifySentinel(dir)).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
