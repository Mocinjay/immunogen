/**
 * corsDetector (web) — WEB-CORS: dangerous live CORS response-header
 * configuration on a screened URL target.
 *
 * Distinct from the existing static `src/detectors/cors-headers/cors-detector.ts`
 * (CORS-01), which scans SOURCE TEXT for a co-occurring wildcard-origin +
 * allow-credentials-true pattern across arbitrary JS/TS/JSON files. This
 * detector instead reads the ACTUAL response headers `fetchTarget` observed
 * on the live target — a strictly more direct signal (it is the header the
 * browser itself would receive), so its ruleId/category is kept distinct
 * (`WEB-CORS` / `web`) rather than reusing `CORS-01`.
 *
 * Severity ladder:
 *   - `access-control-allow-origin: *` together with
 *     `access-control-allow-credentials: true` = HIGH. This combination is
 *     spec-invalid (the Fetch/CORS spec forbids credentialed requests with a
 *     wildcard origin; a compliant browser ignores the credentials flag in
 *     that case) but misconfigured servers still emit it — when they do, it
 *     usually means the server is echoing the request's Origin verbatim
 *     into ACAO while also unconditionally setting allow-credentials, which
 *     IS exploitable (the reflected-origin case below).
 *   - A bare `access-control-allow-origin: *` with NO allow-credentials
 *     header = LOW. This is the legitimate public-API shape (matches this
 *     project's existing CORS-01 FP-mitigation precedent: wildcard alone is
 *     not a real finding, just worth a low-severity informational note).
 *   - A reflected origin (`access-control-allow-origin` present and NOT
 *     literally `*`) together with `access-control-allow-credentials: true`
 *     = MEDIUM — a common "vary based on request Origin" misconfiguration
 *     that effectively allows any origin to make credentialed requests, but
 *     is one step short of the HIGH wildcard+credentials combination (an
 *     attacker still needs to control/spoof the Origin header value the
 *     reflecting logic accepts, which is usually "any value").
 *
 * No-throw contract (mirrors src/core/types.ts `Detector.detect`).
 */
import type { Finding } from "../../core/types.js";
import type { WebContext, WebDetector } from "../types.js";

const ACAO_HEADER = "access-control-allow-origin";
const ACAC_HEADER = "access-control-allow-credentials";

/** True when `value` is exactly the literal `true` string (ACAC only has meaning as this literal). */
function isTrueLiteral(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === "true";
}

function buildFinding(
  targetUrl: string,
  severity: Finding["severity"],
  message: string,
  remediation: string,
  matchedText: string,
): Finding {
  return {
    ruleId: "WEB-CORS",
    category: "web",
    detectorName: "cors",
    file: targetUrl,
    line: 1,
    severity,
    confidence: "HIGH",
    message,
    remediation,
    matchedText,
  };
}

export const webCorsDetector: WebDetector = {
  id: "cors",

  detect(ctx: WebContext): Finding[] {
    try {
      const { target } = ctx;
      const acao = target.headers[ACAO_HEADER];

      if (acao === undefined) {
        // No CORS exposure signal at all — nothing to report.
        return [];
      }

      const acac = target.headers[ACAC_HEADER];
      const credentialsEnabled = isTrueLiteral(acac);
      const isWildcard = acao.trim() === "*";

      if (isWildcard && credentialsEnabled) {
        return [
          buildFinding(
            target.url,
            "HIGH",
            "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is spec-invalid and enables cross-origin credential theft.",
            "Replace the wildcard '*' origin with an explicit allowlisted origin (or a validated dynamic origin-allowlist) whenever Access-Control-Allow-Credentials is enabled.",
            `access-control-allow-origin: *; access-control-allow-credentials: true`,
          ),
        ];
      }

      if (isWildcard) {
        return [
          buildFinding(
            target.url,
            "LOW",
            "Access-Control-Allow-Origin: * is set (no credentials header present — likely an intentional public API).",
            "If this endpoint is not meant to be a fully public API, replace the wildcard origin with an explicit allowlist.",
            "access-control-allow-origin: *",
          ),
        ];
      }

      if (credentialsEnabled) {
        // Non-wildcard ACAO + credentials:true — likely a reflected-origin
        // misconfiguration (server echoes the request Origin back verbatim).
        return [
          buildFinding(
            target.url,
            "MEDIUM",
            `Access-Control-Allow-Origin: ${acao} is set together with Access-Control-Allow-Credentials: true — verify this origin is validated against a strict allowlist, not reflected from the request.`,
            "Validate Origin against a strict server-side allowlist before echoing it into Access-Control-Allow-Origin; never reflect an arbitrary request Origin when credentials are enabled.",
            `access-control-allow-origin: ${acao}; access-control-allow-credentials: true`,
          ),
        ];
      }

      return [];
    } catch {
      return [];
    }
  },
};
