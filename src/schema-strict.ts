import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding, Gate, GateVerdict } from "./types.ts";
import { verdictOf } from "./types.ts";

const f = (ruleId: string, severity: Finding["severity"], file: string, message: string): Finding => ({
  tool: "schema-strict",
  ruleId,
  severity,
  file,
  message,
});

export function checkSchemaStrict(projectPath: string): Finding[] {
  const findings: Finding[] = [];
  const candidateDirs = [join(projectPath, "src"), join(projectPath, "app"), join(projectPath, "api")];

  const scanFiles = (dir: string): string[] => {
    if (!existsSync(dir)) return [];
    try {
      return readdirSync(dir, { recursive: true })
        .map(String)
        .filter((file) => (file.endsWith(".ts") || file.endsWith(".tsx")) && !file.endsWith(".test.ts") && !file.endsWith(".d.ts"));
    } catch {
      return [];
    }
  };

  for (const baseDir of candidateDirs) {
    if (!existsSync(baseDir)) continue;
    const files = scanFiles(baseDir);

    for (const rel of files) {
      const fullPath = join(baseDir, rel);
      let content = "";
      try {
        content = readFileSync(fullPath, "utf8");
      } catch {
        continue;
      }

      const fileRel = relative(projectPath, fullPath);

      if (/@ts-ignore|@ts-nocheck/.test(content)) {
        findings.push(
          f(
            "typescript-suppression-forbidden",
            "critical",
            fileRel,
            "Compiler directive @ts-ignore or @ts-nocheck detected. Production code must resolve type errors explicitly.",
          ),
        );
      }

      if (/(:\s*any\b|\bas\s+any\b|<any>)/.test(content)) {
        findings.push(
          f(
            "untyped-any-forbidden",
            "high",
            fileRel,
            "Explicit 'any' type annotation or cast detected. Production code must define strict domain types.",
          ),
        );
      }

      const isRouteFile = /(api|routes?)[\\/]/.test(fullPath) || /(route|endpoint)\.tsx?$/.test(rel);
      if (isRouteFile && /export\s+(async\s+)?function\s+(POST|PUT|PATCH)/.test(content)) {
        const hasZodValidation = /\.parse\(|\.safeParse\(|validateBody\(|z\.object\(/.test(content);
        if (!hasZodValidation) {
          findings.push(
            f(
              "missing-runtime-schema-validation",
              "high",
              fileRel,
              "State-mutating route handler (POST/PUT/PATCH) lacks runtime schema validation (Zod .parse() / .safeParse()).",
            ),
          );
        }
      }
    }
  }

  return findings;
}

export const schemaStrictGate: Gate = {
  name: "schema-strict",
  run: async (projectPath: string): Promise<GateVerdict> => {
    const findings = checkSchemaStrict(projectPath);
    return verdictOf("schema-strict", findings, new Date().toISOString());
  },
};
