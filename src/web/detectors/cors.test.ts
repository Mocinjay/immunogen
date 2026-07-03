import { describe, expect, it } from "vitest";

import { webCorsDetector } from "./cors.js";

import type { FetchedTarget } from "../fetch-target.js";
import type { WebContext } from "../types.js";

function makeTarget(headers: Record<string, string>, url = "https://example.com/"): FetchedTarget {
  return { url, status: 200, headers, body: "<html></html>", scripts: [], cookies: [] };
}

function makeCtx(target: FetchedTarget): WebContext {
  return { target, probes: [] };
}

describe("webCorsDetector — WEB-CORS (vulnerable)", () => {
  it("flags ACAO:* + ACAC:true as HIGH", () => {
    const findings = webCorsDetector.detect(
      makeCtx(
        makeTarget({
          "access-control-allow-origin": "*",
          "access-control-allow-credentials": "true",
        }),
      ),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-CORS", category: "web", severity: "HIGH" });
  });

  it("flags a bare ACAO:* with no credentials header as LOW", () => {
    const findings = webCorsDetector.detect(makeCtx(makeTarget({ "access-control-allow-origin": "*" })));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-CORS", severity: "LOW" });
  });

  it("flags a reflected (non-wildcard) origin + credentials:true as MEDIUM", () => {
    const findings = webCorsDetector.detect(
      makeCtx(
        makeTarget({
          "access-control-allow-origin": "https://attacker.example",
          "access-control-allow-credentials": "true",
        }),
      ),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "WEB-CORS", severity: "MEDIUM" });
  });
});

describe("webCorsDetector — WEB-CORS (clean)", () => {
  it("yields zero findings when no CORS headers are present at all", () => {
    const findings = webCorsDetector.detect(makeCtx(makeTarget({})));

    expect(findings).toEqual([]);
  });

  it("yields zero findings for a specific allowlisted origin with no credentials header", () => {
    const findings = webCorsDetector.detect(
      makeCtx(makeTarget({ "access-control-allow-origin": "https://trusted.example" })),
    );

    expect(findings).toEqual([]);
  });
});
