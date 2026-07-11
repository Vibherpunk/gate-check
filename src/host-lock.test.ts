import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isHostLockHeld, withHostLock } from "./host-lock.ts";

describe("withHostLock — cross-process mutex for heavy host subprocess work (EPIC #32, 2026-07-09)", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const lockDir = (): string => {
    const d = join(mkdtempSync(join(tmpdir(), "vibehard-hostlock-")), ".host-lock");
    dirs.push(d.replace(/\/\.host-lock$/, ""));
    return d;
  };

  test("runs fn and releases the lock afterward", async () => {
    const dir = lockDir();
    let ranInsideLock = false;
    const result = await withHostLock(
      () => {
        ranInsideLock = isHostLockHeld(dir);
        return "done";
      },
      { lockDir: dir },
    );
    expect(result).toBe("done");
    expect(ranInsideLock).toBe(true);
    expect(isHostLockHeld(dir)).toBe(false); // released
  });

  test("releases the lock even when fn throws", async () => {
    const dir = lockDir();
    await expect(
      withHostLock(
        () => {
          throw new Error("boom");
        },
        { lockDir: dir },
      ),
    ).rejects.toThrow("boom");
    expect(isHostLockHeld(dir)).toBe(false);
  });

  test("a second caller waits for the first to release, then runs — never runs concurrently", async () => {
    const dir = lockDir();
    const order: string[] = [];
    const first = withHostLock(
      async () => {
        order.push("first-start");
        await new Promise((r) => setTimeout(r, 150));
        order.push("first-end");
      },
      { lockDir: dir, pollMs: 20 },
    );
    // Give `first` a moment to actually acquire before `second` starts polling.
    await new Promise((r) => setTimeout(r, 30));
    const second = withHostLock(
      () => {
        order.push("second-start");
      },
      { lockDir: dir, pollMs: 20 },
    );
    await Promise.all([first, second]);
    expect(order).toEqual(["first-start", "first-end", "second-start"]);
  });

  test("a lock held by a dead pid is reclaimed rather than blocking forever", async () => {
    const dir = lockDir();
    mkdirSync(dir, { recursive: true });
    // A pid essentially guaranteed not to exist — simulates a crashed holder.
    writeFileSync(join(dir, "holder.json"), JSON.stringify({ pid: 999_999, at: Date.now() }));
    const result = await withHostLock(() => "recovered", { lockDir: dir, maxWaitMs: 2000, pollMs: 20 });
    expect(result).toBe("recovered");
  });

  test("a stale (too-old) lock is reclaimed even if its pid happens to still exist", async () => {
    const dir = lockDir();
    mkdirSync(dir, { recursive: true });
    // process.pid is definitely alive, but the timestamp is ancient relative to staleMs.
    writeFileSync(join(dir, "holder.json"), JSON.stringify({ pid: process.pid, at: Date.now() - 1_000_000 }));
    const result = await withHostLock(() => "reclaimed", { lockDir: dir, staleMs: 1000, maxWaitMs: 2000, pollMs: 20 });
    expect(result).toBe("reclaimed");
  });

  test("gives up and proceeds WITHOUT the lock if a live holder never releases within maxWaitMs — never hangs a build forever", async () => {
    const dir = lockDir();
    mkdirSync(dir, { recursive: true });
    // process.pid is alive and freshly stamped — a genuinely live, non-stale holder.
    writeFileSync(join(dir, "holder.json"), JSON.stringify({ pid: process.pid, at: Date.now() }));
    const notes: string[] = [];
    const result = await withHostLock(() => "proceeded-anyway", {
      lockDir: dir,
      maxWaitMs: 100,
      pollMs: 20,
      staleMs: 10 * 60_000,
      note: (m) => notes.push(m),
    });
    expect(result).toBe("proceeded-anyway");
    expect(notes.some((n) => n.includes("gave up waiting"))).toBe(true);
  });

  test("isHostLockHeld is false for a nonexistent lock dir", () => {
    expect(isHostLockHeld(join(tmpdir(), "vibehard-hostlock-never-created"))).toBe(false);
  });

  test("acquires the lock even when its parent directory doesn't exist yet (fresh host/container)", async () => {
    // Simulates a genuinely fresh host where e.g. /root/.vibehard/ has never been created —
    // unlike lockDir() above, nothing under the tempdir root exists until acquire() makes it.
    const root = mkdtempSync(join(tmpdir(), "vibehard-hostlock-freshhost-"));
    const dir = join(root, "nested", "deeper", ".host-lock");
    dirs.push(root);
    const result = await withHostLock(() => "acquired-on-fresh-host", { lockDir: dir });
    expect(result).toBe("acquired-on-fresh-host");
    expect(isHostLockHeld(dir)).toBe(false); // released afterward
  });

  test("still mutually excludes two callers when the parent directory has to be created (atomicity preserved)", async () => {
    const root = mkdtempSync(join(tmpdir(), "vibehard-hostlock-freshhost-race-"));
    const dir = join(root, "nested", "deeper", ".host-lock");
    dirs.push(root);
    const order: string[] = [];
    const first = withHostLock(
      async () => {
        order.push("first-start");
        await new Promise((r) => setTimeout(r, 150));
        order.push("first-end");
      },
      { lockDir: dir, pollMs: 20 },
    );
    await new Promise((r) => setTimeout(r, 30));
    const second = withHostLock(
      () => {
        order.push("second-start");
      },
      { lockDir: dir, pollMs: 20 },
    );
    await Promise.all([first, second]);
    expect(order).toEqual(["first-start", "first-end", "second-start"]);
  });
});
