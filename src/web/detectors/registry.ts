/**
 * WEB_DETECTORS registry — every `WebDetector` run by `scan-url.ts` against a
 * single fetched URL target. Mirrors `src/detectors/registry.ts`'s
 * `DEFAULT_DETECTORS` array in spirit (a flat, ordered list of registered
 * detector instances) but far simpler: there is no glob-based file fan-out
 * here (a URL scan has exactly one `WebContext`, not N files), so this module
 * is just the registration list plus a thin `runWebDetectors` fan-out helper.
 */
import { securityHeadersDetector } from "./security-headers.js";
import { webCorsDetector } from "./cors.js";
import { exposedFilesDetector } from "./exposed-files.js";
import { bundleSecretsDetector } from "./bundle-secrets.js";
import { insecureCookiesDetector } from "./insecure-cookies.js";

import type { Finding } from "../../core/types.js";
import type { WebContext, WebDetector } from "../types.js";

/** Every web-probe detector registered by default (WEB-HDR, WEB-CORS, WEB-EXPOSED, WEB-SEC, WEB-COOKIE). */
export const WEB_DETECTORS: WebDetector[] = [
  securityHeadersDetector,
  webCorsDetector,
  exposedFilesDetector,
  bundleSecretsDetector,
  insecureCookiesDetector,
];

/**
 * Runs every detector in `detectors` against `ctx`, flattening the results.
 * Each `WebDetector.detect` call is individually wrapped in a try/catch so
 * one throwing detector (a violation of its own no-throw contract) cannot
 * abort the rest — mirrors the defensive backstop in
 * `src/detectors/registry.ts`'s `runDetectors` (there via
 * `Promise.allSettled`; here synchronously since `WebDetector.detect` is not
 * async).
 */
export function runWebDetectors(ctx: WebContext, detectors: WebDetector[] = WEB_DETECTORS): Finding[] {
  const findings: Finding[] = [];
  for (const detector of detectors) {
    try {
      findings.push(...detector.detect(ctx));
    } catch {
      // No-throw contract backstop — a misbehaving detector contributes zero
      // findings instead of aborting the rest of the web scan.
    }
  }
  return findings;
}
