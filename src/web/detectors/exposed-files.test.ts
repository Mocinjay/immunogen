import { describe, expect, it } from "vitest";

import { exposedFilesDetector } from "./exposed-files.js";

import type { FetchedTarget } from "../fetch-target.js";
import type { ProbeResult, WebContext } from "../types.js";

function makeTarget(): FetchedTarget {
  return {
    url: "https://example.com/",
    status: 200,
    headers: {},
    body: "<html></html>",
    scripts: [],
    cookies: [],
  };
}

function makeCtx(probes: ProbeResult[]): WebContext {
  return { target: makeTarget(), probes };
}

describe("exposedFilesDetector — WEB-EXPOSED (vulnerable)", () => {
  it("flags /.env returning 200 as CRITICAL when the body looks like a dotenv file", () => {
    const findings = exposedFilesDetector.detect(
      makeCtx([{ path: "/.env", status: 200, bodySnippet: "STRIPE_SECRET_KEY=sk_live_abc123\n" }]),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-EXPOSED", severity: "CRITICAL" });
  });

  it("flags /.env returning 200 as HIGH (uncorroborated) when there is no bodySnippet", () => {
    const findings = exposedFilesDetector.detect(makeCtx([{ path: "/.env", status: 200 }]));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-EXPOSED", severity: "HIGH" });
  });

  it("flags /.git/config returning 200 as CRITICAL when the body contains [core]", () => {
    const findings = exposedFilesDetector.detect(
      makeCtx([{ path: "/.git/config", status: 200, bodySnippet: "[core]\n\trepositoryformatversion = 0\n" }]),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-EXPOSED", severity: "CRITICAL" });
  });

  it("flags /.git/HEAD returning 200 as HIGH", () => {
    const findings = exposedFilesDetector.detect(makeCtx([{ path: "/.git/HEAD", status: 200, bodySnippet: "ref: refs/heads/main\n" }]));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-EXPOSED", severity: "HIGH" });
  });

  it("flags /config.json returning 200 as HIGH", () => {
    const findings = exposedFilesDetector.detect(makeCtx([{ path: "/config.json", status: 200 }]));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-EXPOSED", severity: "HIGH" });
  });

  it("flags security.txt returning 200 as INFO only (not a vulnerability)", () => {
    const findings = exposedFilesDetector.detect(makeCtx([{ path: "/.well-known/security.txt", status: 200 }]));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-EXPOSED", severity: "INFO" });
  });

  it("flags a *.js.map path returning 200 as LOW/MEDIUM", () => {
    const findings = exposedFilesDetector.detect(makeCtx([{ path: "/main.js.map", status: 200, bodySnippet: '{"version":3,"mappings":"AAAA"}' }]));

    expect(findings).toHaveLength(1);
    expect(["LOW", "MEDIUM"]).toContain(findings[0]?.severity);
  });
});

describe("exposedFilesDetector — WEB-EXPOSED (clean)", () => {
  it("yields zero findings when every probe returns 404", () => {
    const findings = exposedFilesDetector.detect(
      makeCtx([
        { path: "/.env", status: 404 },
        { path: "/.git/config", status: 404 },
        { path: "/.git/HEAD", status: 404 },
        { path: "/config.json", status: 404 },
        { path: "/.well-known/security.txt", status: 404 },
        { path: "/main.js.map", status: 404 },
      ]),
    );

    expect(findings).toEqual([]);
  });

  it("yields zero findings for an empty probes array", () => {
    expect(exposedFilesDetector.detect(makeCtx([]))).toEqual([]);
  });
});
