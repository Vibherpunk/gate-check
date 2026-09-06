import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkTelemetry, telemetryGate } from "./telemetry.ts";

const tmps: string[] = [];
afterEach(() => {
  for (const d of tmps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function ws(files: Record<string, string> = {}): string {
  const d = mkdtempSync(join(tmpdir(), "gate-telemetry-"));
  tmps.push(d);
  for (const [rel, content] of Object.entries(files)) {
    const full = join(d, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return d;
}

describe("telemetry gate (Law 6)", () => {
  test("clean project with bounded fetch and structured logging passes", async () => {
    const dir = ws({
      "src/client.ts": `
        export async function callApi(url: string) {
          return await fetch(url, { signal: AbortSignal.timeout(5000) });
        }
      `,
    });
    const findings = checkTelemetry(dir);
    expect(findings).toHaveLength(0);
    const v = await telemetryGate.run(dir);
    expect(v.status).toBe("pass");
  });

  test("flags raw console logging as medium severity", async () => {
    const dir = ws({
      "src/logger.ts": `console.log("hello world");`,
      "src/error.ts": `console.error("something failed");`,
    });
    const findings = checkTelemetry(dir);
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.ruleId === "unstructured-console-logging")).toBe(true);
    expect(findings.every((f) => f.severity === "medium")).toBe(true);
  });

  test("flags unbounded fetch calls without timeout as high severity", async () => {
    const dir = ws({
      "src/api.ts": `
        export async function getData(url: string) {
          return await fetch(url);
        }
      `,
    });
    const findings = checkTelemetry(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("unbounded-http-fetch");
    expect(findings[0]!.severity).toBe("high");
    const v = await telemetryGate.run(dir);
    expect(v.status).toBe("block");
  });

  test("passes fetch with controller.signal", async () => {
    const dir = ws({
      "src/api.ts": `
        export async function getData(url: string, controller: AbortController) {
          return await fetch(url, { signal: controller.signal });
        }
      `,
    });
    const findings = checkTelemetry(dir);
    expect(findings).toHaveLength(0);
  });
});
