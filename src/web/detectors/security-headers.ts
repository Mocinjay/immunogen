/**
 * securityHeadersDetector — WEB-HDR: missing/weak response security headers
 * on a live-screened URL target.
 *
 * Checks five well-known response headers against `ctx.target.headers`
 * (already lowercased by `fetchTarget`):
 *   - `content-security-policy` — missing = HIGH (the single strongest
 *     browser-side mitigation against XSS/data-injection; its absence is a
 *     launch-blocking gap, matching this project's existing HDR-01 static
 *     detector's severity intent for the same header).
 *   - `strict-transport-security` (HSTS) — missing = HIGH, but ONLY checked
 *     when the target was actually fetched over `https:` (HSTS is
 *     meaningless over a bare `http://` origin — the browser has no TLS
 *     session to pin, so flagging its absence on an http:// target would be
 *     a pure false positive, not a real gap).
 *   - `x-frame-options` — missing = MEDIUM (clickjacking exposure).
 *   - `x-content-type-options` — missing = MEDIUM (MIME-sniffing exposure).
 *   - `referrer-policy` — missing = LOW (referrer-leak exposure; lowest
 *     impact of the five).
 *
 * Gate: only runs when `ctx.target.status` is a 2xx (200-299) — a non-2xx
 * main response (redirect, 404, 403, 500, ...) is not "an actual served
 * page" in the sense this detector cares about; header hygiene on an error
 * page is not the launch-blocking signal this rule targets, and firing here
 * would just add noise on top of whatever the exposed-files/other detectors
 * already report for a broken target. This is a STATUS gate, not a SCHEME
 * gate — the scheme only gates the individual HSTS check (see above), since
 * CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy are all equally
 * meaningful over http:// or https://.
 *
 * No-throw contract (mirrors src/core/types.ts `Detector.detect`): the whole
 * body runs inside a try/catch returning `[]` on any failure.
 */
import type { Finding } from "../../core/types.js";
import type { WebContext, WebDetector } from "../types.js";

const CSP_HEADER = "content-security-policy";
const HSTS_HEADER = "strict-transport-security";
const XFO_HEADER = "x-frame-options";
const XCTO_HEADER = "x-content-type-options";
const REFERRER_POLICY_HEADER = "referrer-policy";

/** True when `status` falls in the 2xx range — "an actual served page". */
function isSuccessStatus(status: number): boolean {
  return status >= 200 && status < 300;
}

/** Builds one WEB-HDR Finding for a single missing/weak header. */
function buildFinding(
  targetUrl: string,
  headerName: string,
  severity: Finding["severity"],
  message: string,
  remediation: string,
): Finding {
  return {
    ruleId: "WEB-HDR",
    category: "web",
    detectorName: "security-headers",
    file: targetUrl,
    line: 1,
    severity,
    confidence: "HIGH",
    message,
    remediation,
    matchedText: `missing: ${headerName}`,
  };
}

export const securityHeadersDetector: WebDetector = {
  id: "security-headers",

  detect(ctx: WebContext): Finding[] {
    try {
      const { target } = ctx;

      if (!isSuccessStatus(target.status)) {
        return [];
      }

      const findings: Finding[] = [];
      const headers = target.headers;
      const isHttps = target.url.toLowerCase().startsWith("https:");

      // eslint-disable-next-line security/detect-object-injection -- CSP_HEADER is a fixed, code-defined constant, never scanned-response content
      if (headers[CSP_HEADER] === undefined) {
        findings.push(
          buildFinding(
            target.url,
            CSP_HEADER,
            "HIGH",
            "No Content-Security-Policy header on the served page.",
            "Set a Content-Security-Policy header restricting script/style/connect sources to trusted origins.",
          ),
        );
      }

      // HSTS is scheme-gated: meaningless (and not a real gap) over plain http://.
      // eslint-disable-next-line security/detect-object-injection -- HSTS_HEADER is a fixed, code-defined constant, never scanned-response content
      if (isHttps && headers[HSTS_HEADER] === undefined) {
        findings.push(
          buildFinding(
            target.url,
            HSTS_HEADER,
            "HIGH",
            "No Strict-Transport-Security (HSTS) header on an https:// target.",
            "Set Strict-Transport-Security: max-age=31536000; includeSubDomains to force HTTPS on every subsequent visit.",
          ),
        );
      }

      // eslint-disable-next-line security/detect-object-injection -- XFO_HEADER is a fixed, code-defined constant, never scanned-response content
      if (headers[XFO_HEADER] === undefined) {
        findings.push(
          buildFinding(
            target.url,
            XFO_HEADER,
            "MEDIUM",
            "No X-Frame-Options header on the served page.",
            "Set X-Frame-Options: DENY (or SAMEORIGIN) — or an equivalent frame-ancestors CSP directive — to prevent clickjacking.",
          ),
        );
      }

      // eslint-disable-next-line security/detect-object-injection -- XCTO_HEADER is a fixed, code-defined constant, never scanned-response content
      if (headers[XCTO_HEADER] === undefined) {
        findings.push(
          buildFinding(
            target.url,
            XCTO_HEADER,
            "MEDIUM",
            "No X-Content-Type-Options header on the served page.",
            "Set X-Content-Type-Options: nosniff to stop browsers from MIME-sniffing responses away from the declared Content-Type.",
          ),
        );
      }

      // eslint-disable-next-line security/detect-object-injection -- REFERRER_POLICY_HEADER is a fixed, code-defined constant, never scanned-response content
      if (headers[REFERRER_POLICY_HEADER] === undefined) {
        findings.push(
          buildFinding(
            target.url,
            REFERRER_POLICY_HEADER,
            "LOW",
            "No Referrer-Policy header on the served page.",
            "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter) to limit referrer leakage to third parties.",
          ),
        );
      }

      return findings;
    } catch {
      return [];
    }
  },
};
