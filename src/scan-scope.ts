/**
 * Scan scope (PROJECT_BRIEF.md §11). Governing principle: **the gates inspect
 * authored source, never derived/build output.** A real generated app gets built
 * by the verify gate (`.next/`, `dist/`, …), and scanning those artifacts floods
 * sast/secrets with false positives from minified framework code. Two defenses:
 * (1) order the chain so source scanners run BEFORE verify builds (index.ts), and
 * (2) exclude the derived set below as belt-and-suspenders.
 *
 * The §11 fail-closed catch: excluding the derived set could leave a scanner with
 * nothing to read (all-derived or empty project) — which would report a false
 * PASS. `hasAuthoredSource` is the guard: no authored source → the gate trips
 * `scan-failed`, never PASS.
 */
import { readdirSync } from "node:fs";
import { join, relative, isAbsolute } from "node:path";

/** A scanner invoked NATIVELY (no container) reports paths absolute on the host — unlike the
 *  old docker-wrapped invocation, which reported them relative to a container mount point
 *  (`/src/...`) that Finding.file was never actually rewritten out of (found 2026-07-06: this
 *  meant anti-tamper's `join(root, f.file)` on a sast/secrets finding always produced a
 *  nonexistent path, so those findings never populated `flaggedFiles` — a latent protection
 *  gap, fixed as a consequence of this rewrite). Normalize to root-relative here, once, so
 *  every downstream consumer (display, anti-tamper, translate) gets what every other gate's
 *  findings already use. A path outside `root` (shouldn't happen — the scanner was only
 *  pointed at `root`) is left absolute rather than mangled.
 */
export function relativizeFinding(root: string, absoluteFile: string): string {
  if (!absoluteFile || !isAbsolute(absoluteFile)) return absoluteFile;
  const rel = relative(root, absoluteFile);
  if (rel.startsWith("..")) return absoluteFile; // outside root — leave absolute rather than mangle
  return rel === "" ? "." : rel; // a whole-project (scan-failed) finding names the root itself
}

/** Derived/build output — never authored source; excluded from every code scan. */
export const DERIVED_DIRS = [
  "node_modules",
  ".next",
  "dist",
  "build",
  "out",
  "coverage",
  ".turbo",
  ".git",
  ".vibehard", // our own meta dir (the persisted spec/PRD) — never app source
] as const;

const DERIVED = new Set<string>(DERIVED_DIRS);

/**
 * True iff `projectPath` contains at least one file outside the derived dirs —
 * i.e. there is authored source for a scanner to actually read. Recurses, pruning
 * the derived dirs (so it stays fast even with a huge `node_modules`). Returns on
 * the first authored file found.
 */
export function hasAuthoredSource(projectPath: string): boolean {
  try {
    for (const e of readdirSync(projectPath, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (DERIVED.has(e.name)) continue;
        if (hasAuthoredSource(join(projectPath, e.name))) return true;
      } else if (e.isFile()) {
        return true;
      }
    }
  } catch {
    return false; // unreadable / missing target → nothing to scan → fail closed
  }
  return false;
}
