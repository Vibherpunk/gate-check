# @vibehard/gate-check

A deterministic security/quality gate chain for AI-generated code. Point it at a directory; it
tells you, with zero LLM in the verdict path, whether that code is safe to ship.

Built for [VibeHard](https://vibehard.ai)'s own build pipeline — where AI-generated code is
gated before every deploy — and extracted here because the problem ("is this code an AI just
wrote actually safe?") isn't specific to any one app generator.

## What it checks

| Gate | What it catches |
|---|---|
| `sast` | Static analysis (via semgrep) on authored source — injection, unsafe eval, etc. |
| `secrets` | Committed secrets/credentials (via gitleaks) |
| `depvuln` | Known CVEs in declared dependencies (via trivy) |
| `rls` | Missing Row-Level Security on multi-tenant database tables |
| `migrate` | Dangerous or malformed SQL migrations |
| `verify` | Clean-room install + build + boot check — does the app actually start? |
| `completeness` | Does the generated app cover what the spec asked for? (LLM-optional) |
| `compliance`, `pii`, `prod-readiness`, `proptest`, `rls-enforce` | Spec-driven checks — no-ops unless a `.vibehard/spec.json`-shaped spec is present |

Every gate fails **closed**: if a scanner can't run (missing binary, crash, timeout), that's a
block, never a silent pass. A gate whose precondition doesn't apply reports `n/a`, not `pass` —
so an all-`n/a` board is correctly *not* a deploy-ready verdict (nothing was actually verified).

## Install

```bash
bun add @vibehard/gate-check
# or, for the standalone CLI:
bunx @vibehard/gate-check gate ./my-app
```

## CLI usage

```bash
gate-check gate ./my-app      # run every gate, print a report, exit 0/1
gate-check deploy ./my-app    # same, plus stamp a signed sentinel file on a full pass
gate-check ./my-app           # "gate" is the default subcommand
```

Requires `semgrep`, `gitleaks`, and `trivy` on `PATH` for the `sast`/`secrets`/`depvuln` gates
respectively — see [VibeHard's own `Dockerfile`](https://github.com/Vibherpunk/drydock) for the
exact pinned versions this package's gates were built against. A gate whose binary is missing
fails closed (blocks), it doesn't silently skip.

## Library usage

```typescript
import { runGate, deployGate, GATES, printReport } from "@vibehard/gate-check";

// Run the full chain, get a structured verdict:
const result = await runGate("./my-app");
console.log(result.passed, result.verdicts);

// Or gate a deploy — writes a signed sentinel file iff every gate passes:
const outcome = await deployGate("./my-app");
if (outcome.sentinel) {
  // safe to ship
}

// Print the same report the CLI does:
printReport(result);
```

### Running a subset of gates

```typescript
import { runGate, sastGate, secretsGate, depvulnGate } from "@vibehard/gate-check";

const result = await runGate("./my-app", [sastGate, secretsGate, depvulnGate]);
```

### Wiring in a real sandbox / LLM reviewer

Two gates have optional seams this package doesn't default:

- **`verify`** — the clean-room build+boot check runs against local Docker/npm by default. Pass
  a `HostProvider` (`createVerifyGate`) to run it in a real sandbox (Fly, E2B, etc.) instead.
- **`completeness`** — reports a blocking "not configured" finding when a spec with real
  features is present, unless you pass a `FunctionalReviewer` (`createCompletenessGate`,
  or the bundled `llmFunctionalReviewer`) to actually judge output against the spec.

```typescript
import { createVerifyGate, createCompletenessGate, llmFunctionalReviewer } from "@vibehard/gate-check";

const verifyGate = createVerifyGate({ runSandbox: myFlySandboxRunner });
const completenessGate = createCompletenessGate({ reviewer: llmFunctionalReviewer({ config: myLlmConfig }) });
```

## Environment variables

| Variable | Purpose |
|---|---|
| `VIBEHARD_SENTINEL_SECRET` | HMAC key signing `deployGate`'s sentinel file. Unset falls back to a random per-process key (fine for CLI/dev/test; set it for cross-process sentinel verification). |
| `VIBEHARD_HOST_LOCK_DIR` | Overrides the lock directory `sast`/`secrets`/`depvuln` use to serialize concurrent scans on one host. Defaults to `/root/.vibehard/.host-lock` — override this if your process doesn't run as root. |

## Development

```bash
bun install
bun test          # unit tests (fast, no external tools needed for most)
bun test:integration  # also exercises real semgrep/gitleaks/trivy/docker where installed
bun run typecheck
```

## License

MIT
