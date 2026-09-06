import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding, Gate, GateVerdict } from "./types.ts";
import { verdictOf } from "./types.ts";

const f = (ruleId: string, severity: Finding["severity"], file: string, message: string): Finding => ({
  tool: "concurrency-safe",
  ruleId,
  severity,
  file,
  message,
});

export function checkConcurrencySafe(projectPath: string): Finding[] {
  const findings: Finding[] = [];

  // Check 1: Optimistic Concurrency Control in SQL Migrations
  const migDir = join(projectPath, "supabase", "migrations");
  if (existsSync(migDir)) {
    try {
      const sqlFiles = readdirSync(migDir).filter((file) => file.endsWith(".sql"));
      for (const file of sqlFiles) {
        const fullSql = readFileSync(join(migDir, file), "utf8");
        const stateTableRegex = /create\s+table\s+(?:if\s+not\s+exists\s+)?["']?(\w*(?:order|invoice|payment|module|item|inventory|balance|ledger|job|unit)\w*)["']?\s*\(([\s\S]*?)\);/gi;
        let match: RegExpExecArray | null;

        while ((match = stateTableRegex.exec(fullSql)) !== null) {
          const tableName = match[1] ?? "unknown_table";
          const tableBody = match[2] ?? "";

          const hasVersion = /version\s+int(?:eger)?\s+(?:not\s+null\s+)?default\s+1/i.test(tableBody);
          if (!hasVersion) {
            findings.push(
              f(
                "missing-occ-versioning",
                "high",
                join("supabase", "migrations", file),
                `State-bearing table '${tableName}' lacks an Optimistic Concurrency Control column ('version INT NOT NULL DEFAULT 1').`,
              ),
            );
          }
        }
      }
    } catch {
      // Continue
    }
  }

  // Check 2: Idempotency Key validation on POST endpoints
  const candidateDirs = [join(projectPath, "src"), join(projectPath, "app"), join(projectPath, "api")];
  for (const baseDir of candidateDirs) {
    if (!existsSync(baseDir)) continue;
    try {
      const files = readdirSync(baseDir, { recursive: true })
        .map(String)
        .filter((file) => (file.endsWith(".ts") || file.endsWith(".tsx")) && !file.endsWith(".test.ts"));

      for (const rel of files) {
        const fullPath = join(baseDir, rel);
        let content = "";
        try {
          content = readFileSync(fullPath, "utf8");
        } catch {
          continue;
        }

        const isRouteFile = /(api|routes?)[\\/]/.test(fullPath) || /(route|endpoint)\.tsx?$/.test(rel);
        if (isRouteFile && /export\s+(async\s+)?function\s+POST\b/.test(content)) {
          const hasIdempotency = /idempotency-key|idempotencykey|x-idempotency/i.test(content);
          if (!hasIdempotency) {
            findings.push(
              f(
                "missing-idempotency-key",
                "medium",
                relative(projectPath, fullPath),
                "State-mutating POST endpoint does not extract or check an 'Idempotency-Key' header.",
              ),
            );
          }
        }
      }
    } catch {
      // Continue
    }
  }

  return findings;
}

export const concurrencySafeGate: Gate = {
  name: "concurrency-safe",
  run: async (projectPath: string): Promise<GateVerdict> => {
    const findings = checkConcurrencySafe(projectPath);
    return verdictOf("concurrency-safe", findings, new Date().toISOString());
  },
};
