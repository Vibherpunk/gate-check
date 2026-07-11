/**
 * Cross-process mutex serializing HEAVY host subprocess work (npm/pip installs, security
 * scanners, docker builds) across every `vibehard` CLI invocation on one machine (EPIC #32).
 *
 * `Bun.spawnSync` blocks only WITHIN its own process. Two separate CLI invocations — two web
 * requests, two builds, a human retrying while an auto-fix loop is still running — are
 * independent OS processes with no shared JS state, so an in-memory semaphore can't coordinate
 * them. A lock DIRECTORY is the standard POSIX cross-process mutex: `mkdir` is atomic, so
 * "acquire" = a successful mkdir, "release" = rmdir.
 *
 * Found live, 2026-07-09: two concurrent `vibehard fix`/`build` runs on one shared Fly machine
 * starved each other for CPU — semgrep failed to even start ("SAST scan did not run (exit -1)")
 * and an npm install was killed by SIGTERM after blowing through its own timeout. Neither run
 * was individually broken; they were fighting over the same host with zero coordination.
 *
 * This is a stopgap, not the end state: EPIC #32's real architecture moves untrusted execution
 * (install/build/boot) into an ephemeral, resource-capped sandbox — see `verify.ts`'s
 * `VerifyDeps.runSandbox`/`runExecSandbox` seam (2026-07-10: the sandbox provider itself, e.g.
 * VibeHard's Fly-backed one, is injected by the host application, not owned by this package).
 * That removes the heaviest work from the shared host entirely once a sandbox is wired in.
 * Until then — and permanently for the gate scanners, which intentionally stay host-side since
 * they only read source as data (never execute it) — this lock is what keeps concurrent heavy
 * work from starving itself on one machine.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const DEFAULT_LOCK_DIR = "/root/.vibehard/.host-lock";
const DEFAULT_STALE_MS = 10 * 60_000; // a lock older than this is presumed abandoned (crashed holder)
const DEFAULT_POLL_MS = 500;
const DEFAULT_MAX_WAIT_MS = 5 * 60_000; // never block a build forever waiting for the lock

interface Holder {
  pid: number;
  at: number;
}

function readHolder(lockDir: string): Holder | null {
  try {
    return JSON.parse(readFileSync(join(lockDir, "holder.json"), "utf8")) as Holder;
  } catch {
    return null; // unreadable/corrupt/missing → treated as stale by the caller
  }
}

/** True when the lock should be reclaimed: too old, unreadable, or its holder process is gone.
 *  `process.kill(pid, 0)` never sends a signal — it only probes whether the pid still exists. */
function isStale(lockDir: string, staleMs: number): boolean {
  const holder = readHolder(lockDir);
  if (!holder) return true;
  if (Date.now() - holder.at > staleMs) return true;
  try {
    process.kill(holder.pid, 0);
    return false; // holder process is still alive
  } catch {
    return true; // ESRCH — the holder is gone; safe to reclaim
  }
}

async function acquire(lockDir: string, staleMs: number, pollMs: number, maxWaitMs: number): Promise<boolean> {
  const deadline = Date.now() + maxWaitMs;
  for (;;) {
    try {
      // Recursive mkdir on the PARENT only: Node's recursive mkdir silently no-ops when the
      // target already exists (verified — it does NOT throw EEXIST), so running it directly on
      // `lockDir` would defeat the atomicity below and let two processes both "acquire" it.
      // The parent chain has no lock semantics of its own, so concurrent recursive-mkdir racers
      // on it are harmless.
      mkdirSync(dirname(lockDir), { recursive: true });
      mkdirSync(lockDir); // atomic — throws EEXIST if another process already holds it
      writeFileSync(join(lockDir, "holder.json"), JSON.stringify({ pid: process.pid, at: Date.now() }));
      return true;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    if (isStale(lockDir, staleMs)) {
      try {
        rmSync(lockDir, { recursive: true, force: true }); // reclaim; loop retries the mkdir
      } catch {
        /* lost a race with another reclaimer — the next loop iteration sorts it out */
      }
      continue;
    }
    if (Date.now() >= deadline) return false;
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

export interface HostLockOptions {
  /** override the lock directory (tests; VIBEHARD_HOST_LOCK_DIR also works in production) */
  lockDir?: string;
  /** override timing (tests only — production always uses the real defaults) */
  staleMs?: number;
  pollMs?: number;
  maxWaitMs?: number;
  note?: (m: string) => void;
}

/**
 * Run `fn` while holding the host-wide heavy-work lock, releasing it afterward even on throw.
 * Contention is a PERFORMANCE problem, not a correctness one — the opposite of the gate's
 * fail-closed default — so if the lock can't be acquired within `MAX_WAIT_MS` (a genuinely
 * stuck, not-yet-stale holder), this proceeds WITHOUT it rather than hang a build forever.
 */
export async function withHostLock<T>(fn: () => Promise<T> | T, opts: HostLockOptions = {}): Promise<T> {
  const lockDir = opts.lockDir ?? process.env.VIBEHARD_HOST_LOCK_DIR ?? DEFAULT_LOCK_DIR;
  const staleMs = opts.staleMs ?? DEFAULT_STALE_MS;
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS;
  const maxWaitMs = opts.maxWaitMs ?? DEFAULT_MAX_WAIT_MS;
  const got = await acquire(lockDir, staleMs, pollMs, maxWaitMs);
  if (!got) opts.note?.(`host lock: gave up waiting after ${maxWaitMs / 1000}s — proceeding without it`);
  try {
    return await fn();
  } finally {
    if (got) {
      try {
        rmSync(lockDir, { recursive: true, force: true });
      } catch {
        /* best-effort release */
      }
    }
  }
}

/** True when the lock dir exists and its holder looks live — for tests/diagnostics only. */
export function isHostLockHeld(lockDir: string = DEFAULT_LOCK_DIR, staleMs: number = DEFAULT_STALE_MS): boolean {
  return existsSync(lockDir) && !isStale(lockDir, staleMs);
}
