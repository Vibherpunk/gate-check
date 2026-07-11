/**
 * Verify gate — proves a generated app is runnable before deploy
 * (PROJECT_BRIEF.md §12). Ported from ~/dev/gate-proof/gates/verify.sh, then
 * hardened for the two app shapes the generator produces:
 *
 *   • a node SERVER (server.js / package.json main) → launch + probe N times;
 *     one green run proves nothing, so EVERY run must come up healthy.
 *   • a static/SPA BUILD (a `build` script, no server) → `npm run build` must
 *     succeed; a SPA that builds is deployable, and the deploy target serves the
 *     output — so we verify the build, not a dev server (no port/process hazards).
 *
 * Two hardenings learned from dogfooding real generated apps:
 *   • the launch probe tries /health THEN / (root). A generated server app won't
 *     always expose /health, but if it serves ANY 2xx/3xx it has booted — so we
 *     don't false-block a working app for lacking a conventional health route.
 *   • we inject dummy env (synthesized from .env.example) into the build/launch,
 *     so an app that reads required env at boot (e.g. SUPABASE_URL) doesn't crash
 *     on `undefined` and get misjudged as broken.
 *
 * Pure dispositions (`summarizeVerify`, `summarizeBuild`, `detectLaunch`, `isUp`,
 * `synthEnv`) are separated from the I/O (spawning node/npm) and unit-tested; the
 * launches are integration-tested.
 */
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, Gate, GateVerdict } from "./types.ts";
import { verdictOf } from "./types.ts";
import { coerceSpec, decideRigor, type DeployTarget, type Rigor } from "./spec-contract.ts";
import { DERIVED_DIRS } from "./scan-scope.ts";
import { SUBPROCESS_TIMEOUT_MS } from "./timeouts.ts";
import { withHostLock } from "./host-lock.ts";
import { parseBuildErrors } from "./build-errors.ts";
import type { HostProvider, RunSandboxFn, RunExecSandboxFn, SandboxResult } from "./sandbox-seam.ts";

const RUNS = 3; // default when rigor is unknown; see verifyRuns
const PROBE_ATTEMPTS = 30; // ~3s: PROBE_ATTEMPTS × PROBE_INTERVAL_MS
const PROBE_INTERVAL_MS = 100;
const CONTAINER_PORT = 8080; // our Dockerfile convention: the app reads PORT, default 8080
const SHUTDOWN_GRACE_MS = 5000; // §18: a served app must exit on SIGTERM within this
// §18: clean-env install/build under a portable timeout. Split into separate install/build/docker
// budgets 2026-07-10 after direct measurement showed ONE shared number can't fit all three: a real
// `npm install` for a realistic Next.js+Supabase+Tailwind app took 226-256s across two independent
// runs (a single CLEAN_TIMEOUT_MS=120_000 — the original value — SIGTERM-killed it well short); a
// real `npm run build` for the same app took 570s, nearly double what a single "raise it to match
// SUBPROCESS_TIMEOUT_MS (300_000)" fix (the first attempt at this) still allowed. Both measured by
// reproducing the exact failing workspace's install/build by hand with no timeout, not guessed.
// Install and docker-build (which runs BOTH phases inside the Dockerfile, so needs at least their
// sum: ~800s observed) get correspondingly larger margins.
const CLEAN_INSTALL_TIMEOUT_MS = 300_000; // ~1.2x the 226-256s observed
const CLEAN_BUILD_TIMEOUT_MS = 900_000; // ~1.6x the 570s observed
const CLEAN_DOCKER_TIMEOUT_MS = 1_200_000; // covers install+build (~800s observed) + image-layer overhead
/** Probe order: the conventional health route first, then root. The first to
 *  return an "up" status wins — an app serving either has booted. */
const PROBE_PATHS = ["/health", "/"] as const;

/** §18/§16 adaptive rigor: how many launch runs to require. "Pass" = ALL N green —
 *  one flake fails the gate. prototype 1 · default 3 (rigor unknown) · production 5. */
export function verifyRuns(rigor: Rigor | null): number {
  return rigor === "production" ? 5 : rigor === "prototype" ? 1 : 3;
}

/** A server is "up" if it answers with a 2xx — it booted and is actually SERVING a page (B4,
 *  audit2). We previously accepted 3xx too, but `fetch` already FOLLOWS redirects, so a legitimate
 *  "/ → /login" resolves to the final 200 here; a status that is STILL 3xx after following means a
 *  broken/looping redirect that never lands on a served page — not healthy. 4xx/5xx or no answer (0)
 *  also mean it isn't serving. */
export function isUp(status: number): boolean {
  return status >= 200 && status < 300;
}

/** One launch+probe outcome: the HTTP status observed (0 = never came up), plus a
 *  tail of the process output so a boot crash is visible to the operator and the
 *  auto-fix loop (parallels BuildOutcome.log). */
export interface VerifyRun {
  run: number;
  status: number;
  log?: string;
  /** did the process exit on SIGTERM within the grace window (vs needing SIGKILL)? */
  cleanShutdown?: boolean;
}

interface Pkg {
  main?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function readPkg(projectPath: string): Pkg | null {
  const p = join(projectPath, "package.json");
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8")) as Pkg;
  } catch {
    return null;
  }
}

/** Pure: parse the KEYS declared in a dotenv-style file (`KEY=...`, `export KEY=`),
 *  ignoring blanks and `#` comments. We only want the names, not the values. */
export function parseEnvKeys(content: string): string[] {
  const keys: string[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (m) keys.push(m[1]!);
  }
  return keys;
}

/** Pure: a syntactically-plausible dummy for an env var, so an app that reads it
 *  at boot/build doesn't crash on `undefined`. URL-shaped vars get a real URL
 *  (libraries like supabase-js throw on a non-URL); everything else a non-empty
 *  placeholder. This is for *booting*, never for authenticating. */
export function dummyEnvValue(key: string): string {
  const k = key.toUpperCase();
  if (/(URL|URI|ENDPOINT|ORIGIN|HOST)/.test(k)) return "http://localhost:54321";
  if (/PORT/.test(k)) return "3000";
  return "vibehard-verify-placeholder";
}

/** Pure: dummy env map covering every key declared across the given dotenv sources
 *  (e.g. .env.example contents). Real process.env values should override these. */
export function synthEnv(sources: Array<string | null | undefined>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const src of sources) {
    if (!src) continue;
    for (const key of parseEnvKeys(src)) env[key] = dummyEnvValue(key);
  }
  return env;
}

/** Read the project's dotenv TEMPLATES (never a real .env) to learn which env the
 *  app expects, so the launch/build can supply dummies for them. */
function readEnvTemplates(projectPath: string): Array<string | null> {
  const read = (name: string): string | null => {
    const p = join(projectPath, name);
    if (!existsSync(p)) return null;
    try {
      return readFileSync(p, "utf8");
    } catch {
      return null;
    }
  };
  return [read(".env.example"), read(".env.sample"), read(".env.template")];
}

/**
 * Pure: launch outcomes → Finding[]. Blocking unless every required run was
 * healthy (200). A flaky or dead app must not ship. No I/O.
 */
export function summarizeVerify(runs: VerifyRun[], required: number = RUNS, file = "server.js"): Finding[] {
  const healthy = runs.filter((r) => isUp(r.status)).length;
  if (healthy === required && runs.length >= required) return [];
  // Surface the boot error (the last run that logged one) so the failure is
  // actionable — the operator and the auto-fix loop see WHAT crashed. A runtime
  // stack trace LEADS with the cause, so we keep the head (cf. summarizeBuild,
  // which tails because build tools print the error last).
  const log = [...runs].reverse().find((r) => r.log?.trim())?.log?.trim();
  const tail = log ? ` — error: ${log.slice(0, 600)}` : "";
  return [
    {
      tool: "verify",
      ruleId: "health-check-failed",
      severity: "high",
      file,
      message: `launch probe: ${healthy}/${required} runs came up on /health or / — app is not reliably healthy${tail}`,
    },
  ];
}

/** Pure (§18 graceful shutdown): an app that came up but had to be force-killed
 *  (didn't exit on SIGTERM within the grace window) → an advisory. It ran, so this
 *  doesn't block; but it risks dropping in-flight requests on a deploy restart. */
export function summarizeShutdown(runs: VerifyRun[]): Finding[] {
  const unclean = runs.some((r) => isUp(r.status) && r.cleanShutdown === false);
  if (!unclean) return [];
  return [
    {
      tool: "verify",
      ruleId: "unclean-shutdown",
      severity: "medium",
      file: "server.js",
      message: `The app didn't exit within ${SHUTDOWN_GRACE_MS / 1000}s of SIGTERM and had to be force-killed — on a deploy restart or scale-down it may drop in-flight requests. Handle SIGTERM to shut down gracefully.`,
    },
  ];
}

/** Locate the node entry point to launch, relative to `projectPath`. */
export function findEntry(projectPath: string): string | null {
  const pkg = readPkg(projectPath);
  const candidates: string[] = [];
  if (pkg?.main) candidates.push(pkg.main);
  candidates.push("server.js", "index.js", "app.js");
  for (const c of candidates) if (existsSync(join(projectPath, c))) return c;
  return null;
}

/** How to verify a project boots: launch a node server, launch a python server, build a static app, or nothing. */
export type LaunchPlan =
  | { kind: "container" } //                a Dockerfile → build + run the image (the real deploy artifact)
  | { kind: "node"; entry: string }
  | { kind: "cli"; entry: string } //        deployTarget: "downloadable-tool" — run once to completion, no boot probe
  | { kind: "python"; cmd: string[] }
  | { kind: "build"; script: string }
  | null;

/** A Python web entry module (the language-expansion path: any language on Supabase). */
export function pythonEntry(projectPath: string): string | null {
  for (const c of ["main.py", "app.py", "asgi.py", "wsgi.py", "server.py"]) {
    if (existsSync(join(projectPath, c))) return c;
  }
  return null;
}

/**
 * Pure: the launch command for a Python web app, with the port as the literal "$PORT"
 * (substituted at spawn). Pick the server for the framework declared in `deps`
 * (requirements.txt / pyproject text): uvicorn for FastAPI/ASGI; otherwise plain
 * `python <entry>` (Flask/a script reads PORT from the environment). The uvicorn module
 * is the entry minus its `.py`.
 */
export function pythonStartCommand(entry: string, deps: string): string[] {
  const mod = entry.replace(/\.py$/, "");
  if (/\b(uvicorn|fastapi)\b/i.test(deps)) return ["uvicorn", `${mod}:app`, "--host", "0.0.0.0", "--port", "$PORT"];
  return ["python", entry];
}

function readPyDeps(projectPath: string): string {
  return ["requirements.txt", "pyproject.toml"]
    .map((f) => {
      try {
        const p = join(projectPath, f);
        return existsSync(p) ? readFileSync(p, "utf8") : "";
      } catch {
        return "";
      }
    })
    .join("\n");
}

/** Pure-ish (reads package.json / requirements): pick the launch strategy. A node entry
 *  wins, then a Python web app, then a `build` script (static/SPA build-verify). */
export function detectLaunch(projectPath: string): LaunchPlan {
  const isDownloadable = readDeployTarget(projectPath) === "downloadable-tool";
  // A Dockerfile means the deploy artifact IS a container — verify THAT (its own runtime,
  // isolated deps, parity with what the host runs), not a local interpreter. Wins over
  // node/python so a containerized app of ANY language is verified the same correct way —
  // EXCEPT for a downloadable-tool, which never gets deployed at all. A Dockerfile there
  // (belt-and-suspenders: the architecture stage is steered away from ever generating one,
  // but this must not silently trust that) means the container/fly-sandbox-boot path would
  // run — the exact failure observed live, 2026-07-09: a real ephemeral Fly machine spun up
  // to boot-test a container that was never meant to be deployed, and failed. Fall through to
  // the CLI entry-point check instead; a stray Dockerfile is the architecture gate's problem
  // to catch (downloadable-tool-uses-hosted-stack), not verify's problem to run.
  if (!isDownloadable && existsSync(join(projectPath, "Dockerfile"))) return { kind: "container" };
  const entry = findEntry(projectPath);
  if (entry) return isDownloadable ? { kind: "cli", entry } : { kind: "node", entry };
  if (existsSync(join(projectPath, "requirements.txt")) || existsSync(join(projectPath, "pyproject.toml"))) {
    const pe = pythonEntry(projectPath);
    if (pe) return { kind: "python", cmd: pythonStartCommand(pe, readPyDeps(projectPath)) };
  }
  const pkg = readPkg(projectPath);
  if (pkg?.scripts?.build) return { kind: "build", script: "build" };
  return null;
}

/** EPIC #32: a minimal Dockerfile so a `node`/`build` app (no Dockerfile of its own —
 *  that's the "container" plan, already sandboxed) can ALSO run its install/build/boot
 *  in an isolated Fly machine instead of on the platform host. Deps only in the image;
 *  `npm run <script>` (build-kind) or the CMD (node-kind) is what actually exercises the
 *  app's own code, so this stays generic across both callers. `entry` null → a build-only
 *  image whose CMD is never used (the exec sandbox always overrides the command). */
export function synthVerifyDockerfile(entry: string | null): string {
  return [
    "FROM node:20-alpine",
    "WORKDIR /app",
    "COPY package*.json ./",
    "RUN npm install --no-audit --no-fund",
    "COPY . .",
    "EXPOSE 8080",
    "ENV PORT=8080",
    `CMD ["node", ${JSON.stringify(entry ?? "--version")}]`,
    "",
  ].join("\n");
}

/** Outcome of build-verifying a static app — which stage ran, its exit code, and a
 *  tail of the build output (so the auto-fix loop knows WHAT broke, §18). */
export interface BuildOutcome {
  stage: "install" | "build";
  exitCode: number;
  log?: string;
}

/** Pure: a build outcome → Finding[]. A non-zero install or build blocks the deploy.
 *  When `projectPath` is given and the log names specific causes (an unexported symbol,
 *  an unresolved module), emit one PRECISE finding per cause pointing at the real file —
 *  so the fixer is aimed at what to change, not handed `package.json` + a log tail. */
export function summarizeBuild(outcome: BuildOutcome, projectPath?: string): Finding[] {
  if (outcome.exitCode === 0) return [];
  const ruleId = outcome.stage === "install" ? "install-failed" : "build-failed";
  if (outcome.stage === "build" && projectPath && outcome.log) {
    const localized = parseBuildErrors(outcome.log, projectPath, ruleId);
    if (localized.length) return localized;
  }
  const what = outcome.stage === "install" ? "`npm install`" : "`npm run build`";
  const tail = outcome.log?.trim() ? ` — error: ${outcome.log.trim().slice(-600)}` : "";
  return [
    {
      tool: "verify",
      ruleId,
      severity: "high",
      file: "package.json",
      message: `${what} exited ${outcome.exitCode} — the app does not build, so it cannot be deployed${tail}`,
    },
  ];
}

/** A Fly-sandboxed container verify result → findings (EPIC #32a). Mirrors `summarizeBuild`'s
 *  shape: ok → no findings (pass); not ok → one finding carrying the sandbox's log tail. */
export function summarizeSandbox(result: SandboxResult): Finding[] {
  if (result.ok) return [];
  return [
    {
      tool: "verify",
      ruleId: "sandbox-boot-failed",
      severity: "high",
      file: "Dockerfile",
      message: `sandboxed boot did not serve a healthy response (status ${result.status}) — the container cannot be deployed${result.log ? ` — error: ${result.log.slice(-600)}` : ""}`,
    },
  ];
}

function hasDeps(pkg: Pkg): boolean {
  return (
    Object.keys(pkg.dependencies ?? {}).length > 0 || Object.keys(pkg.devDependencies ?? {}).length > 0
  );
}

/** True when node_modules is missing OR STALE relative to package.json — i.e. the
 *  declared deps were changed since the last install. npm stamps a hidden lockfile
 *  (`node_modules/.package-lock.json`) at the end of every install; if package.json
 *  is newer than that stamp, the install on disk no longer satisfies what's declared.
 *  This is the auto-fix loop's load-bearing signal: when the fixer adds a missing
 *  dependency to package.json, the NEXT verify must re-install so the new dep is on
 *  disk before the re-build — otherwise the build keeps failing "Module not found"
 *  on a dep that IS declared, and the fixer oscillates forever (no change to make). */
export function installStale(projectPath: string): boolean {
  if (!existsSync(join(projectPath, "node_modules"))) return true;
  try {
    const stamp = statSync(join(projectPath, "node_modules", ".package-lock.json")).mtimeMs;
    return statSync(join(projectPath, "package.json")).mtimeMs > stamp;
  } catch {
    return true; // no install stamp → can't prove the deps on disk are current → reinstall
  }
}

/** `withHostLock`'s note callback, wired everywhere in this file: a lock wait/timeout is
 *  operational telemetry, not a code defect — it goes to the (tee'd) console, never into the
 *  Finding stream, so it can't pollute severity aggregation or need a translate/dictionary entry. */
function hostLockNote(m: string): void {
  console.error(`[verify] ${m}`);
}

/** Install deps when they are declared but not installed — or no longer match
 *  package.json. A freshly GENERATED app has source but no installed deps, and the
 *  auto-fix loop ADDS deps to package.json between gate runs; both cases need a
 *  (re)install or you can neither build nor launch (a node app dies "Cannot find
 *  module" / a build fails "Module not found"). Both verify paths need this. Returns
 *  null on success/nothing-to-do, or an install BuildOutcome on failure.
 *
 *  Wrapped in the cross-process host lock (EPIC #32): this and the gate scanners are the
 *  heaviest host-side operations, and were the two things that actually starved each other
 *  when two builds ran concurrently on one machine (found live, 2026-07-09). */
async function ensureInstalled(projectPath: string, env: Record<string, string | undefined>): Promise<BuildOutcome | null> {
  const pkg = readPkg(projectPath);
  if (!pkg || !hasDeps(pkg) || !installStale(projectPath)) return null;
  const install = await withHostLock(
    () =>
      Bun.spawnSync(["npm", "install", "--no-audit", "--no-fund", "--ignore-scripts"], {
        cwd: projectPath,
        env,
        stdout: "pipe",
        stderr: "pipe",
        timeout: SUBPROCESS_TIMEOUT_MS,
      }),
    { note: hostLockNote },
  );
  if ((install.exitCode ?? 1) !== 0) {
    return {
      stage: "install",
      exitCode: install.exitCode ?? 1,
      log: `${install.stdout?.toString() ?? ""}${install.stderr?.toString() ?? ""}`,
    };
  }
  return null;
}

/** Install Python deps for a from-source app (pip). Returns a finding on failure, else null. */
async function ensurePythonInstalled(projectPath: string, env: Record<string, string | undefined>): Promise<Finding | null> {
  if (!existsSync(join(projectPath, "requirements.txt"))) return null; // pyproject-only → assume the runtime provides them (v1)
  const install = await withHostLock(
    () => Bun.spawnSync(["pip", "install", "-r", "requirements.txt"], { cwd: projectPath, env, stdout: "pipe", stderr: "pipe", timeout: SUBPROCESS_TIMEOUT_MS }),
    { note: hostLockNote },
  );
  if ((install.exitCode ?? 1) === 0) return null;
  const log = `${install.stdout?.toString() ?? ""}${install.stderr?.toString() ?? ""}`.trim();
  return {
    tool: "verify",
    ruleId: "install-failed",
    severity: "high",
    file: "requirements.txt",
    message: `\`pip install -r requirements.txt\` exited ${install.exitCode} — the app's Python dependencies don't install, so it cannot run${log ? ` — error: ${log.slice(-600)}` : ""}`,
  };
}

/** The MINIMAL host env a build/install toolchain needs to FUNCTION, with NONE of the platform's
 *  secrets (CRITICAL-2). Generated app code is untrusted; spreading the full `process.env`
 *  (FLY_API_TOKEN, OPENCODE_API_KEY, SUPABASE_*, STRIPE_* …) into `npm run build` / `npm install`
 *  would hand those secrets to whatever the LLM wrote. We allowlist only toolchain vars and supply
 *  the app's DECLARED keys as dummies (synthEnv) — exactly what the isolated container branch does. */
const TOOL_ENV_ALLOW = [
  "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE", "TERM",
  "USER", "LOGNAME", "SHELL", "NODE_ENV", "NODE_OPTIONS", "npm_config_cache",
  "npm_config_registry", "npm_config_prefix", "XDG_CACHE_HOME", "SYSTEMROOT", "COMSPEC",
];
export function safeToolEnv(projectPath: string): Record<string, string> {
  const env: Record<string, string> = { ...synthEnv(readEnvTemplates(projectPath)) };
  for (const k of TOOL_ENV_ALLOW) {
    const v = process.env[k];
    if (v !== undefined) env[k] = v;
  }
  return env;
}

/** Install (if needed) then run the build script. Dummy env (from .env.example)
 *  is injected so a build-time env read doesn't fail. */
async function runBuild(projectPath: string, script: string): Promise<BuildOutcome> {
  const env = safeToolEnv(projectPath);
  const installFail = await ensureInstalled(projectPath, env);
  if (installFail) return installFail;
  const build = await withHostLock(() => Bun.spawnSync(["npm", "run", script], { cwd: projectPath, env, stdout: "pipe", stderr: "pipe", timeout: SUBPROCESS_TIMEOUT_MS }), { note: hostLockNote });
  return {
    stage: "build",
    exitCode: build.exitCode ?? 1,
    log: `${build.stdout?.toString() ?? ""}${build.stderr?.toString() ?? ""}`,
  };
}

/** Conventional build-output dirs. Deliberately NOT DERIVED_DIRS: those are dirs the code
 *  scanners must ignore — here they're exactly the artifacts we're looking FOR. */
const ARTIFACT_DIRS = ["dist", "build", "out", ".next", "_site", "public/build"];

/** SECURITY_AUDIT_4 (noted alongside D-1): `npm run build` exiting 0 used to fully satisfy the
 *  build-verify path — a `"build": "true"` script shipped an app with nothing deployable. An
 *  exit-0 build must also leave EVIDENCE: either a conventional output dir with content, or at
 *  least one file written since the build started (covers custom outDirs; the mtime clause alone
 *  would false-block cached no-op rebuilds, which the output-dir clause rescues). Returns a
 *  blocking finding when neither exists, else null. */
export function summarizeBuildArtifacts(projectPath: string, buildStartedMs: number): Finding | null {
  for (const d of ARTIFACT_DIRS) {
    try {
      const dir = join(projectPath, d);
      if (statSync(dir).isDirectory() && readdirSync(dir).length > 0) return null;
    } catch {
      /* dir absent — try the next */
    }
  }
  const newer = (dir: string, depth: number): boolean => {
    if (depth > 6) return false;
    try {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        if (e.name === "node_modules" || e.name === ".git") continue;
        const p = join(dir, e.name);
        try {
          if (e.isDirectory()) {
            if (newer(p, depth + 1)) return true;
          } else if (statSync(p).mtimeMs >= buildStartedMs) return true;
        } catch {
          /* race/unreadable → skip */
        }
      }
    } catch {
      /* unreadable dir → skip */
    }
    return false;
  };
  if (newer(projectPath, 0)) return null;
  return {
    tool: "verify",
    ruleId: "build-no-artifacts",
    severity: "high",
    file: "package.json",
    message:
      "`npm run build` exited 0 but produced no build output — no dist/build/out/.next directory and no file written during the build. " +
      "An exit code alone doesn't prove a deployable artifact; the build script may be a no-op.",
  };
}

/** Read the rigor the front-half persisted (.vibehard/spec.json). Null → unknown
 *  (default rigor — 3 runs, no heavy clean-env check). */
function readRigor(projectPath: string): Rigor | null {
  const p = join(projectPath, ".vibehard", "spec.json");
  if (!existsSync(p)) return null;
  try {
    return decideRigor(coerceSpec(JSON.parse(readFileSync(p, "utf8"))));
  } catch {
    return null;
  }
}

/** Read the deploy target the front-half persisted (.vibehard/spec.json). Null → unknown/missing
 *  (coerceSpec's own default is "hosted-app" — the stricter path — but we return null here, same
 *  as readRigor, so the caller's own "missing → hosted-app behavior" fallback stays explicit). */
function readDeployTarget(projectPath: string): DeployTarget | null {
  const p = join(projectPath, ".vibehard", "spec.json");
  if (!existsSync(p)) return null;
  try {
    return coerceSpec(JSON.parse(readFileSync(p, "utf8"))).deployTarget;
  } catch {
    return null;
  }
}

const COPY_EXCLUDE = new Set<string>(DERIVED_DIRS);

/**
 * Clean-env verify (§18): prove a FRESH machine can install + build — copy the
 * AUTHORED source (no node_modules / derived) to a temp dir, install from scratch
 * (`npm ci` if a lockfile, else `npm install`), then build. Catches "works on my
 * machine": an undeclared dependency that's present locally, or lockfile drift. Heavy
 * (a from-scratch install) → run at production rigor only, ONCE, before the loop.
 */
async function cleanEnvVerify(projectPath: string, env: Record<string, string | undefined>): Promise<Finding[]> {
  const pkg = readPkg(projectPath);
  if (!pkg || !hasDeps(pkg)) return []; // nothing to install → not applicable
  let tmp: string;
  try {
    tmp = mkdtempSync(join(tmpdir(), "vibehard-clean-"));
  } catch (e) {
    return [cleanFinding("copy", String(e))]; // §11 fail-closed: couldn't run the check
  }
  try {
    cpSync(projectPath, tmp, {
      recursive: true,
      // skip derived dirs by basename → a fresh tree, like a clean checkout
      filter: (src) => !COPY_EXCLUDE.has(src.split("/").pop() ?? ""),
    });
    // Both spawns share ONE lock acquisition (EPIC #32) — this is a from-scratch install +
    // build, the single heaviest operation in the whole gate chain; re-acquiring between the
    // two steps would just let another process's heavy work wedge itself in the middle.
    return await withHostLock(
      () => {
        const cmd = existsSync(join(tmp, "package-lock.json"))
          ? ["npm", "ci", "--no-audit", "--no-fund", "--ignore-scripts"]
          : ["npm", "install", "--no-audit", "--no-fund", "--ignore-scripts"];
        const install = Bun.spawnSync(cmd, { cwd: tmp, env, stdout: "pipe", stderr: "pipe", timeout: CLEAN_INSTALL_TIMEOUT_MS });
        if ((install.exitCode ?? 1) !== 0) {
          return [cleanFinding("install", `${install.stdout?.toString() ?? ""}${install.stderr?.toString() ?? ""}`)];
        }
        if (pkg.scripts?.build) {
          const build = Bun.spawnSync(["npm", "run", "build"], { cwd: tmp, env, stdout: "pipe", stderr: "pipe", timeout: CLEAN_BUILD_TIMEOUT_MS });
          if ((build.exitCode ?? 1) !== 0) {
            const log = `${build.stdout?.toString() ?? ""}${build.stderr?.toString() ?? ""}`;
            // localize against projectPath (the source the fixer edits) — the same relative
            // files exist in the clean copy, so the resolved paths are valid for both.
            const localized = parseBuildErrors(log, projectPath, "clean-verify-failed");
            return localized.length ? localized : [cleanFinding("build", log)];
          }
        }
        return [];
      },
      { note: hostLockNote },
    );
  } catch (e) {
    return [cleanFinding("copy", String(e))];
  } finally {
    try {
      rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* best-effort cleanup */
    }
  }
}

/** BuildKit's own "failed to solve" framing is a recognizable signature of the SANDBOX'S OWN
 *  image build failing (the synthesized Dockerfile's baked-in `RUN npm install`, most often) —
 *  distinct from the actual sandboxed COMMAND failing inside an already-built image. Found live,
 *  2026-07-09: a held finding claimed "`npm run build` exited 1" while its own captured log was
 *  unmistakably Docker/Depot build output ("load build definition from dockerfile", "failed to
 *  solve: process ... npm install ... did not complete successfully") — `npm run build` never
 *  even ran. Mislabeling this sends whoever reads it (a human, or the autofix LLM) chasing the
 *  app's build SCRIPT when the real problem is one layer down, in the sandbox's own image. */
function isSandboxImageBuildFailure(log: string): boolean {
  return /failed to solve:|error building:|load build definition from dockerfile/i.test(log);
}

/** A sandboxed exec's result → the finding that actually describes what failed. `describeCmd` is
 *  what to call the thing that was SUPPOSED to run (e.g. "`npm run build`") when it's genuinely
 *  that which failed; `onCommandFailure` builds that finding (the existing, already-correct path
 *  for a real command failure) — this only intercepts the image-build-failed case ahead of it. */
function sandboxExecFinding(result: { exitCode: number; log: string }, describeCmd: string, onCommandFailure: (log: string) => Finding[]): Finding[] {
  if (result.exitCode === 0) return [];
  if (isSandboxImageBuildFailure(result.log)) {
    const trimmed = result.log.trim();
    return [
      {
        tool: "verify",
        ruleId: "sandbox-image-build-failed",
        severity: "high",
        file: "Dockerfile",
        message: `The isolated sandbox couldn't even build its own image — before ${describeCmd} ever ran. This is usually the Dockerfile's own baked-in dependency install failing, not your app's build script${trimmed ? ` — error: ${trimmed.slice(-600)}` : ""}`,
      },
    ];
  }
  return onCommandFailure(result.log);
}

/** Pure: a `cli` launch kind's run outcome → Finding[]. Shared by the local (Bun.spawnSync) and
 *  sandboxed (Fly exec, EPIC #32) paths so both produce the IDENTICAL finding shape — the fixer
 *  and any UI keyed on ruleId shouldn't have to know which path actually ran the command. */
function cliRunFinding(entry: string, exitCode: number, log: string): Finding[] {
  if (exitCode === 0) return [];
  const trimmed = log.trim();
  return [
    {
      tool: "verify",
      ruleId: "cli-run-failed",
      severity: "high",
      file: entry,
      message: `\`node ${entry}\` exited ${exitCode} — the CLI tool did not run cleanly${trimmed ? ` — error: ${trimmed.slice(-600)}` : ""}`,
    },
  ];
}

/** Run a downloadable-tool's entry point ONCE, to completion — no port probe. This is the inverse
 *  of the server paths above: there, the process staying up (serving) is success; here, a CLI/script
 *  RUNNING TO COMPLETION and exiting 0 is success — the process exiting is the expected outcome, not
 *  a crash. Bounded by CLEAN_INSTALL_TIMEOUT_MS — a one-shot script run, not a full install/build,
 *  so the smaller of the from-scratch budgets already gives it generous headroom. `env` carries the
 *  same dummy/safe env every other path uses (safeToolEnv) — never the host's real secrets. */
async function runCliOnce(projectPath: string, entry: string, env: Record<string, string | undefined>): Promise<Finding[]> {
  const run = await withHostLock(() => Bun.spawnSync(["node", entry], { cwd: projectPath, env, stdout: "pipe", stderr: "pipe", timeout: CLEAN_INSTALL_TIMEOUT_MS }), { note: hostLockNote });
  const exitCode = run.exitCode ?? 1;
  const log = `${run.stdout?.toString() ?? ""}${run.stderr?.toString() ?? ""}`;
  return cliRunFinding(entry, exitCode, log);
}

function cleanFinding(stage: "copy" | "install" | "build", log: string): Finding {
  const what = stage === "build" ? "`npm run build`" : stage === "install" ? "`npm ci` / `npm install`" : "copying the source";
  const tail = log.trim() ? ` — error: ${log.trim().slice(-500)}` : "";
  return {
    tool: "verify",
    ruleId: "clean-verify-failed",
    severity: "high",
    file: "package.json",
    message: `On a clean machine (fresh copy, no node_modules), ${what} failed — the app works locally but not from scratch (an undeclared dependency or lockfile drift)${tail}`,
  };
}

/** Try each probe path once; return the first "up" status, else 0. Redirects are
 *  followed, so a `/ → /login` app resolves to its real page status. */
async function probePaths(port: number): Promise<number> {
  for (const path of PROBE_PATHS) {
    try {
      const res = await fetch(`http://localhost:${port}${path}`);
      if (isUp(res.status)) return res.status;
    } catch {
      /* this path not reachable yet — try the next */
    }
  }
  return 0;
}

/** A Docker image tag for a project's verify build — deterministic from the dir name. */
export function dockerTag(projectPath: string): string {
  const base =
    (projectPath.split("/").filter(Boolean).pop() || "app")
      .toLowerCase()
      .replace(/[^a-z0-9._-]/g, "-")
      .replace(/^[-._]+|[-._]+$/g, "") // docker names can't start/end with a separator
      .slice(0, 40)
      .replace(/[-._]+$/, "") || "app";
  return `vibehard-verify-${base}`;
}

/** Build the app's Docker image (the deploy artifact). Returns a finding on failure, else null.
 *  Only reached when no sandbox (`deps.flyHost`/`runSandbox`/`runExecSandbox`) is injected — the
 *  local fallback, so a docker build competing for host CPU is exactly the EPIC #32 lock's job. */
async function buildContainerImage(projectPath: string, tag: string): Promise<Finding | null> {
  const build = await withHostLock(() => Bun.spawnSync(["docker", "build", "-t", tag, "."], { cwd: projectPath, stdout: "pipe", stderr: "pipe", timeout: CLEAN_DOCKER_TIMEOUT_MS }), { note: hostLockNote });
  if ((build.exitCode ?? 1) === 0) return null;
  const log = `${build.stdout?.toString() ?? ""}${build.stderr?.toString() ?? ""}`.trim();
  return {
    tool: "verify",
    ruleId: "build-failed",
    severity: "high",
    file: "Dockerfile",
    message: `\`docker build\` exited ${build.exitCode} — the container image doesn't build, so it cannot be deployed${log ? ` — error: ${log.slice(-600)}` : ""}`,
  };
}

/** Run the built image once (dummy env — NEVER the host's real secrets), probe it, tear it
 *  down. The container runs the app in its TARGET runtime, so we verify what actually ships. */
async function probeContainerOnce(tag: string, hostPort: number, env: Record<string, string>): Promise<{ status: number; log: string; cleanShutdown: boolean }> {
  const name = `${tag}-${hostPort}`;
  Bun.spawnSync(["docker", "rm", "-f", name], { stdout: "ignore", stderr: "ignore" }); // clear any stale container
  const args = ["docker", "run", "-d", "--name", name, "-p", `${hostPort}:${CONTAINER_PORT}`, "-e", `PORT=${CONTAINER_PORT}`];
  for (const [k, v] of Object.entries(env)) args.push("-e", `${k}=${v}`);
  args.push(tag);
  const run = Bun.spawnSync(args, { stdout: "pipe", stderr: "pipe", timeout: SUBPROCESS_TIMEOUT_MS });
  if ((run.exitCode ?? 1) !== 0) {
    return { status: 0, log: `${run.stderr?.toString() ?? ""}`.trim(), cleanShutdown: true };
  }
  let status = 0;
  let log = "";
  try {
    for (let i = 0; i < PROBE_ATTEMPTS; i++) {
      await Bun.sleep(PROBE_INTERVAL_MS);
      status = await probePaths(hostPort);
      if (status) break;
    }
  } finally {
    const logs = Bun.spawnSync(["docker", "logs", name], { stdout: "pipe", stderr: "pipe" }); // capture a boot crash before removal
    log = `${logs.stdout?.toString() ?? ""}${logs.stderr?.toString() ?? ""}`.trim();
    Bun.spawnSync(["docker", "rm", "-f", name], { stdout: "ignore", stderr: "ignore" });
  }
  return { status, log, cleanShutdown: true };
}

/** Launch `node <entry>` in `projectPath` on `port`, poll until it comes up on any
 *  probe path (or the budget is spent), tear down. `env` carries dummy app env.
 *  Returns the status and a tail of the process output (captured so a boot crash
 *  is visible — drained after teardown; a boot stack trace is far under the cap). */
async function probeOnce(
  projectPath: string,
  cmd: string[],
  port: number,
  env: Record<string, string | undefined>,
): Promise<{ status: number; log: string; cleanShutdown: boolean }> {
  const resolved = cmd.map((a) => (a === "$PORT" ? String(port) : a)); // port templated for uvicorn etc.
  const proc = Bun.spawn(resolved, {
    cwd: projectPath,
    env: { ...env, PORT: String(port) }, // node/Flask read PORT from env; uvicorn from --port
    stdout: "pipe",
    stderr: "pipe",
  });
  let status = 0;
  let cleanShutdown = true;
  try {
    for (let i = 0; i < PROBE_ATTEMPTS; i++) {
      await Bun.sleep(PROBE_INTERVAL_MS);
      status = await probePaths(port);
      if (status) break;
    }
  } finally {
    // §18 graceful shutdown: SIGTERM, then up to SHUTDOWN_GRACE_MS to exit. A clean
    // app exits at once (the sleep is abandoned); one that hangs is force-killed and
    // marked unclean. (A well-behaved process adds ~0ms here.)
    proc.kill(); // SIGTERM
    const exited = await Promise.race([proc.exited.then(() => true), Bun.sleep(SHUTDOWN_GRACE_MS).then(() => false)]);
    if (!exited) {
      cleanShutdown = false;
      proc.kill(9); // SIGKILL
      await proc.exited.catch(() => {});
    }
  }
  const out = await new Response(proc.stdout).text().catch(() => "");
  const err = await new Response(proc.stderr).text().catch(() => "");
  // Prefer stderr — that's where a crash trace lands; fall back to stdout.
  return { status, log: err.trim() || out.trim(), cleanShutdown };
}

export interface VerifyDeps {
  /** Injectable sandbox HostProvider for the container path's sandboxed build+boot (EPIC #32a —
   *  untrusted generated code must never execute on the platform host). gate-check has no opinion
   *  on which sandbox provider this is (Fly, another cloud, a local VM) — the host application
   *  wires one in via `flyHost`/`runSandbox`/`runExecSandbox` together. Any of the three omitted
   *  → falls back to the LOCAL docker build+run path below (today's default behavior — what every
   *  package-level test/CI run hits, since none of them inject a sandbox). */
  flyHost?: HostProvider;
  /** Runs one command (install/build/CLI-run) inside the injected sandbox. Required alongside
   *  `flyHost` to actually reach the sandboxed build/node/cli paths. */
  runExecSandbox?: RunExecSandboxFn;
  /** Deploys + health-probes the injected sandbox for the container/node DEPLOY path. Required
   *  alongside `flyHost` to reach the sandboxed container/node paths. */
  runSandbox?: RunSandboxFn;
  /** Injectable deps forwarded as-is to `runExecSandbox`'s own optional 4th argument (its shape is
   *  owned by whichever sandbox implementation the host application wired in, not by gate-check). */
  flyExec?: unknown;
  /** Injectable HTTP probe for the container/node sandboxed DEPLOY path's health check (threads
   *  through to `runSandbox`'s `fetchImpl`). Tests inject this so a "the sandbox came up healthy"
   *  pass case is actually testable without a real deployed URL to hit; production leaves it
   *  undefined and the real `runSandbox` implementation uses real fetch. */
  flySandboxFetch?: SandboxDeploySeamFetch;
}

type SandboxDeploySeamFetch = (url: string) => Promise<{ status: number }>;

/** Verify `projectPath` boots: launch-probe a server, or build-verify a static app. */
export async function runVerify(
  projectPath: string,
  ranAt: string = new Date().toISOString(),
  deps: VerifyDeps = {},
): Promise<GateVerdict> {
  const plan = detectLaunch(projectPath);

  if (!plan) {
    return verdictOf(
      "verify",
      [
        {
          tool: "verify",
          ruleId: "no-entry-point",
          severity: "high",
          file: projectPath,
          message:
            "no launchable entry point (package.json main / server.js) and no build script — cannot verify the app boots",
        },
      ],
      ranAt,
    );
  }

  const env = safeToolEnv(projectPath);
  const rigor = readRigor(projectPath);
  const findings: Finding[] = [];

  // §18 clean-env verify (production rigor, heavy): prove a fresh machine can
  // install + build. Runs ONCE, before the path-specific check.
  if (rigor === "production") findings.push(...(await cleanEnvVerify(projectPath, env)));

  // Containerized app: build + boot it in its own runtime — the actual deploy artifact, the
  // right language version + isolated deps. Dummy env only (never the host's real secrets).
  if (plan.kind === "container") {
    // EPIC #32a: prefer an ISOLATED, ephemeral sandbox over building/running the untrusted image
    // on the platform host — the whole point of the sandbox seam (host-application-provided).
    // Only available when the host application injected one; falls back to local docker below
    // otherwise (unchanged path, what CI/every package-level test hits).
    const flyHost = deps.flyHost;
    if (flyHost && deps.runSandbox) {
      const containerEnv = synthEnv(readEnvTemplates(projectPath));
      const result = await deps.runSandbox(projectPath, containerEnv, { host: flyHost, fetchImpl: deps.flySandboxFetch });
      findings.push(...summarizeSandbox(result));
      return verdictOf("verify", findings, ranAt);
    }
    const tag = dockerTag(projectPath);
    const buildFinding = await buildContainerImage(projectPath, tag);
    if (buildFinding) {
      findings.push(buildFinding);
      return verdictOf("verify", findings, ranAt);
    }
    const required = verifyRuns(rigor);
    const containerEnv = synthEnv(readEnvTemplates(projectPath));
    const runs: VerifyRun[] = [];
    for (let i = 1; i <= required; i++) {
      runs.push({ run: i, ...(await probeContainerOnce(tag, 4200 + i, containerEnv)) });
    }
    findings.push(...summarizeVerify(runs, required, "Dockerfile"));
    Bun.spawnSync(["docker", "rmi", "-f", tag], { stdout: "ignore", stderr: "ignore" }); // best-effort image cleanup
    return verdictOf("verify", findings, ranAt);
  }

  if (plan.kind === "build") {
    // EPIC #32: same "prefer an isolated sandbox over the host" preference as container kind
    // above — `npm install && npm run build` is untrusted, generated-code execution too.
    const flyHost = deps.flyHost;
    if (flyHost && deps.runExecSandbox) {
      const dockerfile = synthVerifyDockerfile(null);
      const result = await deps.runExecSandbox(projectPath, dockerfile, ["sh", "-c", `npm run ${plan.script}`], deps.flyExec);
      // Sandboxed: no local filesystem access to the build output (it lived inside the now-torn-down
      // machine), so summarizeBuildArtifacts (a LOCAL disk check) can't run here — same tradeoff the
      // container path already accepts (summarizeSandbox trusts the sandbox's own signal, no extra
      // local check). The exit code + log tail from inside the sandbox is the whole verdict.
      findings.push(...sandboxExecFinding(result, `\`npm run ${plan.script}\``, (log) => summarizeBuild({ stage: "build", exitCode: result.exitCode, log }, projectPath)));
      return verdictOf("verify", findings, ranAt);
    }
    const startedMs = Date.now();
    const outcome = await runBuild(projectPath, plan.script);
    findings.push(...summarizeBuild(outcome, projectPath));
    if (outcome.exitCode === 0) {
      const noArtifacts = summarizeBuildArtifacts(projectPath, startedMs);
      if (noArtifacts) findings.push(noArtifacts);
    }
    return verdictOf("verify", findings, ranAt);
  }

  // deployTarget: "downloadable-tool" — a runnable CLI/script, not a server. Fundamentally
  // different from every path above: there is no port to probe and no "stayed up" signal to
  // wait for. Install deps if needed, run the entry ONCE to completion, and judge it purely on
  // exit code — exiting 0 IS success here (unlike the node path below, where the process exiting
  // means it crashed before ever coming up).
  if (plan.kind === "cli") {
    // EPIC #32: same "prefer an isolated sandbox over the host" preference as the container/build
    // paths above — installing deps + running a downloadable tool's own entry point is untrusted,
    // generated-code execution too. Until now this was the one launch kind with no sandbox wiring
    // at all, regardless of whether a sandbox host was configured.
    const flyHost = deps.flyHost;
    if (flyHost && deps.runExecSandbox) {
      const dockerfile = synthVerifyDockerfile(null);
      const result = await deps.runExecSandbox(projectPath, dockerfile, ["node", plan.entry], deps.flyExec);
      findings.push(...sandboxExecFinding(result, `\`node ${plan.entry}\``, (log) => cliRunFinding(plan.entry, result.exitCode, log)));
      return verdictOf("verify", findings, ranAt);
    }
    const installFail = await ensureInstalled(projectPath, env);
    if (installFail) {
      findings.push(...summarizeBuild(installFail));
      return verdictOf("verify", findings, ranAt);
    }
    findings.push(...(await runCliOnce(projectPath, plan.entry, env)));
    return verdictOf("verify", findings, ranAt);
  }

  // EPIC #32: a launched node server is the same "boots the real, untrusted generated code"
  // risk as the container path — sandbox it the same way when a sandbox host is configured.
  // python stays local for now (containerizing it correctly is a separate, later scope).
  if (plan.kind === "node") {
    const flyHost = deps.flyHost;
    if (flyHost && deps.runSandbox) {
      // Transient — written for the duration of the sandboxed deploy, ALWAYS removed after
      // (mirrors a real HostProvider's own fly.toml-equivalent handling). Left behind, a next
      // gate run's detectLaunch would misclassify this as a real "container" app forever.
      const dockerfilePath = join(projectPath, "Dockerfile");
      writeFileSync(dockerfilePath, synthVerifyDockerfile(plan.entry));
      try {
        const containerEnv = synthEnv(readEnvTemplates(projectPath));
        const result = await deps.runSandbox(projectPath, containerEnv, { host: flyHost, fetchImpl: deps.flySandboxFetch });
        findings.push(...summarizeSandbox(result));
        return verdictOf("verify", findings, ranAt);
      } finally {
        rmSync(dockerfilePath, { force: true });
      }
    }
  }

  // A launched app (node or python) can't run without its deps; a fresh generation has none yet.
  if (plan.kind === "python") {
    const f = await ensurePythonInstalled(projectPath, env);
    if (f) {
      findings.push(f);
      return verdictOf("verify", findings, ranAt);
    }
  } else {
    const installFail = await ensureInstalled(projectPath, env);
    if (installFail) {
      findings.push(...summarizeBuild(installFail));
      return verdictOf("verify", findings, ranAt);
    }
  }
  const launchCmd = plan.kind === "node" ? ["node", plan.entry] : plan.cmd;
  // §18 adaptive: ALL N runs must come up healthy (N scales with rigor).
  const required = verifyRuns(rigor);
  const runs: VerifyRun[] = [];
  for (let i = 1; i <= required; i++) {
    const { status, log, cleanShutdown } = await probeOnce(projectPath, launchCmd, 4100 + i, env);
    runs.push({ run: i, status, log, cleanShutdown });
  }
  findings.push(...summarizeVerify(runs, required), ...summarizeShutdown(runs));
  return verdictOf("verify", findings, ranAt);
}

// Bare default: no sandbox injected, so every launch kind falls back to the local docker/npm path
// (unchanged behavior for standalone use with no sandbox provider configured at all).
export const verifyGate: Gate = { name: "verify", run: (p: string) => runVerify(p) };

/** Construct a verify gate bound to a specific sandbox (e.g. VibeHard's own gate-wiring layer,
 *  passing `flyHost: process.env.FLY_API_TOKEN ? new FlyHostProvider() : undefined, runSandbox:
 *  runInFlySandbox, runExecSandbox: runInFlyExecSandbox`) — what a host application uses in place
 *  of the bare `verifyGate` to actually reach the sandboxed build/boot paths. */
export function createVerifyGate(deps: VerifyDeps): Gate {
  return { name: "verify", run: (p: string) => runVerify(p, undefined, deps) };
}

/** FAST proxy of verify, for the inner fix loop: just the in-place build (`npm run build` =
 *  the compile/type check, which catches the vast majority of failures) WITHOUT the heavy
 *  clean-room install, container build, or N boot probes. Iterating against this is seconds,
 *  not minutes; the FULL runVerify runs ONCE at convergence to confirm no regression + the real
 *  artifact. A pure launched app (no build script) can't be cheaply proxied → full verify. */
export async function runVerifyFast(projectPath: string, ranAt: string = new Date().toISOString()): Promise<GateVerdict> {
  const pkg = readPkg(projectPath);
  if (!pkg?.scripts?.build) return runVerify(projectPath, ranAt);
  const startedMs = Date.now();
  const outcome = await runBuild(projectPath, "build");
  const findings = summarizeBuild(outcome, projectPath);
  if (outcome.exitCode === 0) {
    const noArtifacts = summarizeBuildArtifacts(projectPath, startedMs);
    if (noArtifacts) findings.push(noArtifacts);
  }
  return verdictOf("verify", findings, ranAt);
}
export const fastVerifyGate: Gate = { name: "verify", run: (p: string) => runVerifyFast(p) };

/** FAST proxy variant of `createVerifyGate` — same sandbox deps, the cheap in-place build path.
 *  Note: `runVerifyFast` doesn't currently thread `deps` through to a sandboxed path itself (the
 *  fast proxy is a local in-place build regardless); this seam exists for API symmetry with
 *  `createVerifyGate` and so a future fast-path sandbox story has somewhere to attach without
 *  another signature change. */
export function createFastVerifyGate(_deps: VerifyDeps): Gate {
  return { name: "verify", run: (p: string) => runVerifyFast(p) };
}
