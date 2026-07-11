/**
 * Production-readiness gate (PROJECT_BRIEF.md §19, §17 Tier 1). Deterministic,
 * install-free file checks that make a build safe to hand to a client / ship:
 *   • dependency pinning — no unbounded version ranges that let a silent upgrade
 *     break a shipped app;
 *   • README — present + non-trivial (matters for "agency hands a build to a client");
 *   • container hygiene (if a Dockerfile) — non-root USER, base image pinned by
 *     digest, a .dockerignore;
 *   • a lint signal — TypeScript strict mode on (install-free; the full linter run,
 *     eslint/ruff/tsc, is deferred — verify's build already type-checks JS/TS).
 *
 * §16 ADAPTIVE RIGOR: block at production, warn at prototype (`applyRigor` downgrades
 * blockers to advisories below production). The gate is CLASSIFICATION-DRIVEN like
 * compliance — it reads the rigor from the spec the front-half persisted
 * (.vibehard/spec.json) and is a no-op without it. Pure checks split from the I/O.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding, GateVerdict } from "./types.ts";
import { notApplicable, verdictOf } from "./types.ts";
import { coerceSpec, decideRigor, type Rigor } from "./spec-contract.ts";

const f = (ruleId: string, severity: Finding["severity"], file: string, message: string): Finding => ({
  tool: "prod-readiness",
  ruleId,
  severity,
  file,
  message,
});

/** Pure: dependency specifiers with an UNBOUNDED upper version (`latest`, `*`, `x`,
 *  `>=`, `>`). Bounded ranges (`^`/`~`/exact) are fine — a lockfile pins them; an
 *  unbounded range lets a future major silently land in a shipped app. */
export function checkPinning(deps: Record<string, string>): Finding[] {
  const unbounded: string[] = [];
  for (const [name, raw] of Object.entries(deps)) {
    const range = String(raw).trim();
    if (/^(latest|\*|x)$/i.test(range) || /^\d+(\.\d+)?\.x$/i.test(range) || /^[><]=?/.test(range)) {
      unbounded.push(`${name}@${range}`);
    }
  }
  if (!unbounded.length) return [];
  return [f("unpinned-dependency", "high", "package.json", `Dependencies use unbounded version ranges, so a silent upgrade could land in a shipped build and break it: ${unbounded.join(", ")}. Pin these to exact or bounded (^/~) versions.`)];
}

/** Pure: a README must exist and be non-trivial (has a heading + some content). */
export function checkReadme(content: string | null): Finding[] {
  if (content && content.trim().length >= 200 && /^#/m.test(content)) return [];
  return [
    f(
      "missing-readme",
      "medium",
      "README.md",
      content
        ? "The README is too thin — say what the app does, how to run it, and what it needs (e.g. env vars)."
        : "No README — add a short one (what the app does, how to run it, the env vars it needs); it matters when handing the build to someone else.",
    ),
  ];
}

/** Pure: Dockerfile hygiene — runs as non-root, base pinned by digest, .dockerignore. */
export function checkContainer(dockerfile: string | null, hasDockerignore: boolean): Finding[] {
  if (!dockerfile) return [];
  const out: Finding[] = [];
  if (!/^\s*USER\s+(?!root\b)\S+/im.test(dockerfile)) {
    out.push(f("container-runs-as-root", "high", "Dockerfile", "The container has no non-root USER, so it runs as root — a compromise then has full container privileges. Add a non-root USER."));
  }
  if (!/^\s*FROM\s+\S+@sha256:[0-9a-f]{64}/im.test(dockerfile)) {
    // A model asked to "pin by digest" has no way to know a real registry digest and will
    // fabricate plausible-looking hex — the autofix loop resolves and injects the real one
    // deterministically (normalizeDockerfile in autofix.ts) before this ever reaches a fixer
    // round in the common case. This message only reaches the model when that lookup failed
    // (offline, private registry) — so it must NOT ask for a digest it can't actually know.
    out.push(f("unpinned-base-image", "high", "Dockerfile", "The base image isn't pinned by digest (@sha256:…), so the build isn't reproducible and could pull a changed image. Use a specific version tag (never `latest` or no tag) — do not hand-write a @sha256 digest yourself, since a fabricated one will fail to resolve and break the build; a concrete tag is enough for the platform to pin automatically."));
  }
  if (!hasDockerignore) {
    out.push(f("missing-dockerignore", "medium", "Dockerfile", "No .dockerignore — local files and secrets (.env, node_modules, .git) can leak into the build context. Add one."));
  }
  return out;
}

/** Pure: a TypeScript project should compile in strict mode (install-free lint signal). */
export function checkTsStrict(tsconfig: string | null): Finding[] {
  if (!tsconfig) return [];
  try {
    const cfg = JSON.parse(tsconfig) as { compilerOptions?: { strict?: boolean } };
    if (cfg.compilerOptions?.strict === true) return [];
  } catch {
    // malformed tsconfig → fall through to the advisory
  }
  return [f("typescript-not-strict", "medium", "tsconfig.json", "TypeScript strict mode is off — strict catches whole classes of bugs (null/undefined, implicit any) before they ship. Enable `\"strict\": true`.")];
}

/** Pure: §16 adaptive rigor. At production, findings keep their severity; below it,
 *  blockers (high/critical) are downgraded to advisories (warn, not block). */
export function applyRigor(findings: Finding[], rigor: Rigor): Finding[] {
  if (rigor === "production") return findings;
  return findings.map((x) => (x.severity === "high" || x.severity === "critical" ? { ...x, severity: "medium" } : x));
}

// ── I/O ──────────────────────────────────────────────────────────────────────

function readFirst(projectPath: string, names: string[]): string | null {
  for (const name of names) {
    const p = join(projectPath, name);
    if (existsSync(p)) {
      try {
        return readFileSync(p, "utf8");
      } catch {
        return null;
      }
    }
  }
  return null;
}

/** Run the production-readiness checks. No persisted spec → no-op (the gate is
 *  rigor-driven and only assesses apps that went through the front-half). */
export async function runProdReadiness(projectPath: string, ranAt: string = new Date().toISOString()): Promise<GateVerdict> {
  const specPath = join(projectPath, ".vibehard", "spec.json");
  if (!existsSync(specPath)) return notApplicable("prod-readiness", ranAt);

  let rigor: Rigor = "production"; // fail-closed: an unreadable spec is treated as production-strict
  try {
    rigor = decideRigor(coerceSpec(JSON.parse(readFileSync(specPath, "utf8"))));
  } catch {
    /* keep production */
  }

  let deps: Record<string, string> = {};
  const pkgRaw = readFirst(projectPath, ["package.json"]);
  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      deps = { ...pkg.dependencies, ...pkg.devDependencies };
    } catch {
      /* malformed package.json — pinning check just sees no deps */
    }
  }

  const findings = [
    ...checkPinning(deps),
    ...checkReadme(readFirst(projectPath, ["README.md", "README", "readme.md"])),
    ...checkContainer(readFirst(projectPath, ["Dockerfile", "dockerfile"]), existsSync(join(projectPath, ".dockerignore"))),
    ...checkTsStrict(readFirst(projectPath, ["tsconfig.json"])),
  ];
  return verdictOf("prod-readiness", applyRigor(findings, rigor), ranAt);
}

export const prodReadinessGate = { name: "prod-readiness", run: (p: string) => runProdReadiness(p) };
