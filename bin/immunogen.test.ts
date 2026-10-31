/**
 * Unit test for the CLI action (bin/immunogen.ts). Imports only
 * `runCli` — the module-scope commander wiring + `parseAsync()` is guarded
 * by an entry-script check (realpath of `process.argv[1]` === realpath of this module)
 * so importing this module under vitest never triggers real argv parsing.
 */
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runCli } from "./immunogen.js";

import type { SarifLog } from "../src/reporters/sarif-types.js";

const WITH_SECRET_FIXTURE = "tests/fixtures/scan/with-secret";
const CLEAN_FIXTURE = "tests/fixtures/scan/clean";
const MCP_TOOL_POISONING_FIXTURE = "tests/fixtures/vulnerable-apps/mcp-tool-poisoning";

let captured: string;

beforeEach(() => {
  captured = "";
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    captured += String(chunk);
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runCli — exit codes derived from verdict (criterion 4)", () => {
  it("resolves to 1 for the with-secret (blocked) fixture and prints the score", async () => {
    const exitCode = await runCli(WITH_SECRET_FIXTURE, { format: "terminal" });

    expect(exitCode).toBe(1);
    expect(captured.length).toBeGreaterThan(0);
    expect(captured).toMatch(/\d+/);
  });

  it("resolves to 0 for the clean fixture", async () => {
    const exitCode = await runCli(CLEAN_FIXTURE, { format: "terminal" });

    expect(exitCode).toBe(0);
  });
});

describe("runCli — --format json produces valid, parseable ScanResult JSON (criterion 2)", () => {
  it("writes output that JSON.parse-es to an object with a score property", async () => {
    await runCli(WITH_SECRET_FIXTURE, { format: "json" });

    const parsed = JSON.parse(captured) as { score?: unknown };
    expect(parsed).toHaveProperty("score");
  });
});

describe("runCli — --format sarif produces valid SARIF 2.1.0 through the CLI seam", () => {
  it("writes output that JSON.parse-es to a SARIF 2.1.0 document with rules[] and partialFingerprints on every result", async () => {
    await runCli(MCP_TOOL_POISONING_FIXTURE, { format: "sarif" });

    const parsed = JSON.parse(captured) as SarifLog;

    expect(parsed.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(parsed.version).toBe("2.1.0");

    const run = parsed.runs[0];
    expect(run).toBeDefined();
    expect(run?.tool.driver.rules.length).toBeGreaterThanOrEqual(1);
    expect(run?.results.length).toBeGreaterThanOrEqual(1);
    for (const result of run?.results ?? []) {
      const hash: string = result.partialFingerprints.primaryLocationLineHash;
      expect(typeof hash).toBe("string");
      expect(hash.length).toBeGreaterThan(0);
    }
  });
});

describe("runCli — graceful degradation on ingestion failure (exit code 2, distinct from verdict-blocked's 1)", () => {
  it("resolves to 2 and writes a single clean 'immunogen: <message>' stderr line for a nonexistent path", async () => {
    const stderrSpy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);

    const exitCode = await runCli("./this-path-does-not-exist-12345", { format: "terminal" });

    expect(exitCode).toBe(2);
    expect(stderrSpy).toHaveBeenCalledTimes(1);
    const written = String(stderrSpy.mock.calls[0]?.[0]);
    expect(written).toMatch(/^immunogen: /);
    expect(written).not.toMatch(/ENOENT|at Object|at async|node_modules/);
    // No stdout write on the failure path — only the stderr line.
    expect(captured).toBe("");

    stderrSpy.mockRestore();
  });

  it("resolves to 2 for a file-as-path input (not a raw ENOTDIR stack trace)", async () => {
    const stderrSpy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);

    const exitCode = await runCli("package.json", { format: "terminal" });

    expect(exitCode).toBe(2);
    const written = String(stderrSpy.mock.calls[0]?.[0]);
    expect(written).toMatch(/^immunogen: /);
    expect(written).not.toMatch(/ENOTDIR/);

    stderrSpy.mockRestore();
  });
});

describe("runCli — --no-llm forces llmEnriched:false (07-03 CLI flag path)", () => {
  it("resolves with llmEnriched:false in JSON output for the with-secret fixture", async () => {
    await runCli(WITH_SECRET_FIXTURE, { format: "json", noLlm: true });

    const parsed = JSON.parse(captured) as { llmEnriched?: unknown };
    expect(parsed.llmEnriched).toBe(false);
  });
});

describe("runCli — live-URL screening consent gate (--authorize wiring)", () => {
  it("resolves to 2 and writes a clean actionable stderr line for a URL with no --authorize (no stack trace)", async () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const exitCode = await runCli("https://example.com", { format: "terminal" });

    expect(exitCode).toBe(2);
    expect(stderrSpy).toHaveBeenCalledTimes(1);
    const written = String(stderrSpy.mock.calls[0]?.[0]);
    expect(written).toMatch(/^immunogen: /);
    expect(written).toMatch(/authorization/i);
    expect(written).not.toMatch(/at Object|at async|node_modules/);
    expect(captured).toBe("");

    stderrSpy.mockRestore();
  });

  it("resolves to 2 and writes a clean actionable stderr line for a private host with --authorize but no --allow-private", async () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const exitCode = await runCli("http://127.0.0.1", { format: "terminal", authorize: true });

    expect(exitCode).toBe(2);
    const written = String(stderrSpy.mock.calls[0]?.[0]);
    expect(written).toMatch(/^immunogen: /);
    expect(written).toMatch(/private|loopback/i);

    stderrSpy.mockRestore();
  });
});

describe("bin/immunogen.ts — thin-wrapper guard (criterion 5)", () => {
  it("contains no detection/scoring/AST-parsing logic — only delegates to scan() and getReporter", () => {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is this test's own sibling source file, derived from import.meta.url, never from scanned-repo content
    const source = readFileSync(new URL("./immunogen.ts", import.meta.url), "utf8");

    expect(source).not.toMatch(/computeScore/);
    expect(source).not.toMatch(/runDetectors/);
    expect(source).not.toMatch(/@babel/);
    expect(source).not.toMatch(/ingest\(/);

    expect(source).toMatch(/getReporter/);
    expect(source).toMatch(/scan\(/);
  });
});
