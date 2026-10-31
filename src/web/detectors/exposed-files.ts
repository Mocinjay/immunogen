/**
 * exposedFilesDetector — WEB-EXPOSED: sensitive well-known paths that
 * resolve to a 200 response on the live-screened target.
 *
 * Consumes `ctx.probes` (populated by `scan-url.ts` — see that module's
 * `EXPOSED_FILE_PROBE_PATHS` list) rather than performing any fetch itself;
 * this detector is a pure post-processing pass over already-gathered probe
 * results, matching this file's sibling detectors' no-I/O design.
 *
 * Severity per path:
 *   - `/.env` and `/.git/config` / `/.git/HEAD` returning 200 = a real
 *     secret/source leak. Base severity HIGH; raised to CRITICAL when the
 *     probe's `bodySnippet` corroborates the leak is genuine (an `.env` body
 *     containing a `KEY=value`-shaped line, or a `.git/config` body
 *     containing the `[core]` INI section header) rather than e.g. a
 *     catch-all SPA route that happens to 200 on every path.
 *   - `/config.json` returning 200 = HIGH (a generic but still
 *     commonly-secret-bearing config-dump path).
 *   - `/.well-known/security.txt` returning 200 = INFORMATIONAL only (this
 *     is the OPPOSITE of a vulnerability — RFC 9116 security.txt is a
 *     best-practice disclosure-contact file — so this is reported at INFO
 *     severity/LOW confidence rather than treated as a leak).
 *   - Any `*.js.map` path returning 200 = LOW/MEDIUM (a source-map leak
 *     exposes original, unminified source — real but lower-impact than a
 *     credential leak). MEDIUM when there is corroborating evidence the
 *     body actually looks like a source map (`"mappings"` key present);
 *     LOW otherwise.
 *
 * A probe with any status other than 200 contributes no finding: a 3xx/4xx/
 * 5xx on any of these paths just means "not exposed here" and is the
 * expected, non-vulnerable outcome — most of these paths SHOULD 404. Probes
 * never follow redirects (scan-url.ts), so a redirect to a login or home
 * page is a 3xx here, not a 200.
 *
 * Catch-all routes: single-page apps and many hosts answer EVERY path with
 * `200 index.html`. A 200 whose content-type is HTML, or whose body is an
 * HTML document, is therefore treated as "not exposed" for every path except
 * security.txt — a real `.env`, git file, JSON config or source map is never
 * HTML. `/config.json` additionally has to look like JSON.
 *
 * No-throw contract (mirrors src/core/types.ts `Detector.detect`).
 */
import type { Finding, Severity } from "../../core/types.js";
import type { ProbeResult, WebContext, WebDetector } from "../types.js";

/** True when `body` looks like a genuine dotenv file: at least one `KEY=value`-shaped line. */
function looksLikeDotenv(body: string): boolean {
  return /^[A-Z][A-Z0-9_]*\s*=.+$/m.test(body);
}

/** True when `body` looks like a genuine git config: contains the `[core]` INI section header. */
function looksLikeGitConfig(body: string): boolean {
  return /\[core\]/.test(body);
}

/** True when the probe answered with an HTML page — the signature of a catch-all route, not of the file asked for. */
function isHtmlResponse(probe: ProbeResult): boolean {
  if (probe.contentType !== undefined && /\btext\/html\b/i.test(probe.contentType)) {
    return true;
  }
  return probe.bodySnippet !== undefined && /^\s*(?:<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>])/i.test(probe.bodySnippet);
}

/** True when `body` plausibly starts a JSON document. */
function looksLikeJson(body: string): boolean {
  return /^\s*[{[]/.test(body);
}

/** True when `body` looks like a genuine source map: contains the `"mappings"` key every source map JSON carries. */
function looksLikeSourceMap(body: string): boolean {
  return /"mappings"\s*:/.test(body);
}

/** The absolute URL of `probePath` on the target's origin (no `//` when the target ends in `/`). */
function probeUrl(targetUrl: string, probePath: string): string {
  try {
    return new URL(probePath, targetUrl).toString();
  } catch {
    return `${targetUrl.replace(/\/+$/, "")}${probePath}`;
  }
}

function buildFinding(
  targetUrl: string,
  probePath: string,
  severity: Severity,
  confidence: Finding["confidence"],
  message: string,
  remediation: string,
): Finding {
  return {
    ruleId: "WEB-EXPOSED",
    category: "web",
    detectorName: "exposed-files",
    file: probeUrl(targetUrl, probePath),
    line: 1,
    severity,
    confidence,
    message,
    remediation,
    matchedText: `${probePath} -> 200`,
  };
}

/** Handles the `/.env` probe path. */
function detectEnvLeak(targetUrl: string, probe: ProbeResult): Finding | undefined {
  const corroborated = probe.bodySnippet !== undefined && looksLikeDotenv(probe.bodySnippet);
  return buildFinding(
    targetUrl,
    probe.path,
    corroborated ? "CRITICAL" : "HIGH",
    corroborated ? "HIGH" : "MEDIUM",
    "A .env file is publicly served at this path, potentially leaking secrets/credentials.",
    "Remove .env from the deployed/served directory (add it to your build's exclude list) and rotate any credentials it may have contained.",
  );
}

/** Handles the `/.git/config` and `/.git/HEAD` probe paths. */
function detectGitLeak(targetUrl: string, probe: ProbeResult): Finding | undefined {
  const corroborated =
    probe.path.endsWith("config") && probe.bodySnippet !== undefined && looksLikeGitConfig(probe.bodySnippet);
  return buildFinding(
    targetUrl,
    probe.path,
    corroborated ? "CRITICAL" : "HIGH",
    corroborated ? "HIGH" : "MEDIUM",
    "The .git directory is publicly served at this path, potentially leaking full source history.",
    "Block access to /.git/ at the web-server/CDN level (e.g. deny-all rule for dotfiles) and remove the .git directory from the deployed artifact entirely.",
  );
}

/** Handles the `/config.json` probe path — only a JSON body counts. */
function detectConfigJsonLeak(targetUrl: string, probe: ProbeResult): Finding | undefined {
  if (probe.bodySnippet !== undefined && !looksLikeJson(probe.bodySnippet)) {
    return undefined;
  }
  return buildFinding(
    targetUrl,
    probe.path,
    "HIGH",
    "MEDIUM",
    "A config.json file is publicly served at this path, which commonly carries API keys/endpoints not meant for public exposure.",
    "Remove config.json from the served/public directory or confirm it contains no secrets before leaving it public.",
  );
}

/** Handles the `/.well-known/security.txt` probe path — informational only, NOT a vulnerability. */
function detectSecurityTxt(targetUrl: string, probe: ProbeResult): Finding {
  return {
    ruleId: "WEB-EXPOSED",
    category: "web",
    detectorName: "exposed-files",
    file: probeUrl(targetUrl, probe.path),
    line: 1,
    severity: "INFO",
    confidence: "LOW",
    message: "security.txt is published at this path (RFC 9116) — informational, not a vulnerability.",
    remediation: "No action needed; this is a best-practice disclosure-contact file.",
    matchedText: `${probe.path} -> 200`,
  };
}

/** Handles any `*.js.map` probe path. */
function detectSourceMapLeak(targetUrl: string, probe: ProbeResult): Finding {
  const corroborated = probe.bodySnippet !== undefined && looksLikeSourceMap(probe.bodySnippet);
  return buildFinding(
    targetUrl,
    probe.path,
    corroborated ? "MEDIUM" : "LOW",
    corroborated ? "MEDIUM" : "LOW",
    "A JavaScript source map is publicly served, exposing original unminified/uncompiled source.",
    "Do not deploy .js.map files to production (disable sourcemap generation for production builds, or exclude *.map from the deployed artifact).",
  );
}

export const exposedFilesDetector: WebDetector = {
  id: "exposed-files",

  detect(ctx: WebContext): Finding[] {
    try {
      const findings: Finding[] = [];

      for (const probe of ctx.probes) {
        if (probe.status !== 200) {
          continue;
        }
        if (probe.path !== "/.well-known/security.txt" && isHtmlResponse(probe)) {
          // A catch-all route answering with the app shell — not the file.
          continue;
        }

        if (probe.path === "/.env") {
          const finding = detectEnvLeak(ctx.target.url, probe);
          if (finding) findings.push(finding);
          continue;
        }
        if (probe.path === "/.git/config" || probe.path === "/.git/HEAD") {
          const finding = detectGitLeak(ctx.target.url, probe);
          if (finding) findings.push(finding);
          continue;
        }
        if (probe.path === "/config.json") {
          const finding = detectConfigJsonLeak(ctx.target.url, probe);
          if (finding) findings.push(finding);
          continue;
        }
        if (probe.path === "/.well-known/security.txt") {
          findings.push(detectSecurityTxt(ctx.target.url, probe));
          continue;
        }
        if (probe.path.endsWith(".js.map")) {
          findings.push(detectSourceMapLeak(ctx.target.url, probe));
          continue;
        }
      }

      return findings;
    } catch {
      return [];
    }
  },
};
