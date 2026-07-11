/**
 * The optional sandboxed-build seam. `verify.ts`'s clean-room checks prefer running untrusted,
 * generated app code (npm install/build, the app's own server boot) in an isolated, ephemeral
 * environment rather than on whatever host is running gate-check — but gate-check itself has no
 * opinion on WHICH sandbox provider that is (Fly, another cloud, a local VM). The host application
 * injects a `HostProvider` + the two run functions; without them, verify falls back to its local
 * docker/npm path (unchanged default behavior — every test and CI run hits this).
 *
 * VibeHard's own Fly-specific implementation (`src/substrate/fly.ts`, `fly-sandbox.ts`,
 * `fly-exec-sandbox.ts`) lives outside this package and is wired in by VibeHard's own gate-wiring
 * layer — this file only defines the shapes, never a concrete provider.
 */

/** Deploy + tear down an ephemeral host for one sandboxed run. */
export interface HostProvider {
  readonly name: string;
  deploy(workspacePath: string, env: Record<string, string>, hostRef: string | null): Promise<{ url: string; hostRef: string }>;
  teardown(hostRef: string): Promise<void>;
}

export interface SandboxResult {
  /** the app booted and served a healthy (2xx) response in the isolated environment */
  ok: boolean;
  status: number;
  url: string | null;
  /** error detail when the deploy/build failed (never the app's secrets) */
  log: string;
}

export interface SandboxDeploySeam {
  host: HostProvider;
  fetchImpl?: (url: string) => Promise<{ status: number }>;
}

/** Deploy `workspacePath` to an isolated host and probe it; tears the host down unconditionally. */
export type RunSandboxFn = (workspacePath: string, env: Record<string, string>, deps: SandboxDeploySeam) => Promise<SandboxResult>;

export interface ExecSandboxResult {
  exitCode: number;
  log: string;
}

/** Run one command inside an isolated, ephemeral environment (an install/build/CLI-run step that
 *  never needs a served port) — the exec-only counterpart to `RunSandboxFn`'s deploy+probe shape. */
export type RunExecSandboxFn = (projectPath: string, dockerfile: string, cmd: string[], deps?: unknown) => Promise<ExecSandboxResult>;
