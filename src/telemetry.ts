import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding, Gate, GateVerdict } from "./types.ts";
import { verdictOf } from "./types.ts";

const f = (ruleId: string, severity: Finding["severity"], file: string, message: string): Finding => ({
  tool: "telemetry",
  ruleId,
  severity,
  file,
  message,
});

export function checkTelemetry(projectPath: string): Finding[] {
  const findings: Finding[] = [];
  const srcDir = join(projectPath, "src");
  if (!existsSync(srcDir)) return [];

  try {
    const files = readdirSync(srcDir, { recursive: true })
      .map(String)
      .filter((file) => (file.endsWith(".ts") || file.endsWith(".tsx")) && !file.endsWith(".test.ts"));

    for (const rel of files) {
      const fullPath = join(srcDir, rel);
      let content = "";
      try {
        content = readFileSync(fullPath, "utf8");
      } catch {
        continue;
      }

      const fileRel = relative(projectPath, fullPath);

      if (/console\.(log|info|warn|error)\(/.test(content)) {
        findings.push(
          f(
            "unstructured-console-logging",
            "medium",
            fileRel,
            "Raw console.log detected. Production services must emit structured JSON logs ({ timestamp, level, trace_id, event, message }).",
          ),
        );
      }

      if (/fetch\(/.test(content)) {
        const hasTimeout = /AbortSignal\.timeout|signal:\s*controller\.signal|signal:\s*timeoutSignal/.test(content);
        if (!hasTimeout) {
          findings.push(
            f(
              "unbounded-http-fetch",
              "high",
              fileRel,
              "Outbound fetch() lacks an explicit timeout (AbortSignal.timeout(ms)). Unbounded HTTP calls cause socket starvation.",
            ),
          );
        }
      }
    }
  } catch {
    // Continue
  }

  return findings;
}

export const telemetryGate: Gate = {
  name: "telemetry",
  run: async (projectPath: string): Promise<GateVerdict> => {
    const findings = checkTelemetry(projectPath);
    return verdictOf("telemetry", findings, new Date().toISOString());
  },
};
