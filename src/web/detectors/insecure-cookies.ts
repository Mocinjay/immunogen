/**
 * insecureCookiesDetector — WEB-COOKIE: session-shaped cookies missing
 * `Secure`, `HttpOnly`, or a strong `SameSite` attribute.
 *
 * Parses `ctx.target.cookies` — raw `Set-Cookie` header strings, exactly as
 * `fetchTarget` surfaced them (see that module's `extractSetCookies`
 * comment: it deliberately does NOT split multi-cookie semantics itself,
 * since `Set-Cookie` is the one header the Fetch API cannot safely
 * comma-fold). This detector does the per-cookie attribute parsing itself —
 * a `Set-Cookie` line's OWN internal `;`-separated attribute list is
 * unambiguous (unlike folding multiple `Set-Cookie` headers together), so a
 * plain `.split(";")` text pass is safe and needs no HTML/cookie-jar
 * library, matching this project's zero-extra-dependency convention.
 *
 * A cookie is only evaluated when it LOOKS like a session/auth cookie — its
 * name (case-insensitively) contains one of `session`, `sid`, `auth`, or
 * `token`. Cookies with unrelated names (e.g. an analytics/consent cookie)
 * are skipped entirely: this project's false-positive-rate goal means an
 * ordinary marketing cookie missing HttpOnly should NOT generate noise.
 *
 * Severity per missing attribute, applied independently per cookie (a
 * cookie missing multiple attributes gets multiple findings — one per
 * missing attribute — so a report clearly enumerates every gap rather than
 * collapsing them into one vague message):
 *   - Missing `Secure` = MEDIUM (the cookie can be sent over plain HTTP,
 *     exposing it to network-level interception).
 *   - Missing `HttpOnly` = MEDIUM (the cookie is readable by page JS, so any
 *     XSS on the site can exfiltrate it directly).
 *   - Missing or weak `SameSite` (absent, or explicitly `None` without
 *     `Secure` — though the no-`Secure` case is already covered by the
 *     Secure check above) = LOW (CSRF exposure; lower than the two MEDIUMs
 *     above since modern browsers already default an absent SameSite to
 *     `Lax`, which provides partial protection on its own).
 *
 * No-throw contract (mirrors src/core/types.ts `Detector.detect`).
 */
import type { Finding, Severity } from "../../core/types.js";
import type { WebContext, WebDetector } from "../types.js";

/** Case-insensitive substrings a cookie NAME must contain at least one of to be treated as session-shaped. */
const SESSION_NAME_MARKERS = ["session", "sid", "auth", "token"];

/** True when `name` (case-insensitive) contains any SESSION_NAME_MARKERS substring. */
function looksLikeSessionCookieName(name: string): boolean {
  const lower = name.toLowerCase();
  return SESSION_NAME_MARKERS.some((marker) => lower.includes(marker));
}

/** One parsed `Set-Cookie` header's name plus its attribute set (attribute names lowercased). */
interface ParsedCookie {
  name: string;
  attributes: Set<string>;
  sameSiteValue: string | undefined;
}

/**
 * Parses a single raw `Set-Cookie` header string into its cookie name plus a
 * lowercased attribute-name set (`secure`, `httponly`, `samesite`, ...) and
 * SameSite's own value (when present). The first `;`-separated segment is
 * always the `name=value` pair; every subsequent segment is either a bare
 * flag (`Secure`, `HttpOnly`) or a `key=value` attribute (`SameSite=Lax`,
 * `Path=/`, `Max-Age=3600`, ...).
 */
function parseSetCookie(raw: string): ParsedCookie {
  const segments = raw.split(";").map((segment) => segment.trim());
  const first = segments[0] ?? "";
  const name = first.split("=")[0]?.trim() ?? "";

  const attributes = new Set<string>();
  let sameSiteValue: string | undefined;

  for (const segment of segments.slice(1)) {
    if (segment.length === 0) continue;
    const [rawKey, rawValue] = segment.split("=");
    const key = (rawKey ?? "").trim().toLowerCase();
    attributes.add(key);
    if (key === "samesite") {
      sameSiteValue = rawValue?.trim();
    }
  }

  return { name, attributes, sameSiteValue };
}

/** True when a SameSite value is considered "strong" — Lax or Strict (case-insensitive). Absent or "None" is weak. */
function hasStrongSameSite(cookie: ParsedCookie): boolean {
  if (!cookie.attributes.has("samesite")) {
    return false;
  }
  const value = cookie.sameSiteValue?.toLowerCase();
  return value === "lax" || value === "strict";
}

function buildFinding(
  targetUrl: string,
  cookieName: string,
  severity: Severity,
  attribute: string,
  message: string,
  remediation: string,
): Finding {
  return {
    ruleId: "WEB-COOKIE",
    category: "web",
    detectorName: "insecure-cookies",
    file: targetUrl,
    line: 1,
    severity,
    confidence: "HIGH",
    message,
    remediation,
    matchedText: `${cookieName}: missing ${attribute}`,
  };
}

export const insecureCookiesDetector: WebDetector = {
  id: "insecure-cookies",

  detect(ctx: WebContext): Finding[] {
    try {
      const findings: Finding[] = [];

      for (const raw of ctx.target.cookies) {
        const cookie = parseSetCookie(raw);
        if (!looksLikeSessionCookieName(cookie.name)) {
          continue;
        }

        if (!cookie.attributes.has("secure")) {
          findings.push(
            buildFinding(
              ctx.target.url,
              cookie.name,
              "MEDIUM",
              "Secure",
              `Session-like cookie '${cookie.name}' is missing the Secure attribute — it can be sent over plain HTTP.`,
              "Add the Secure attribute so this cookie is only ever sent over HTTPS.",
            ),
          );
        }

        if (!cookie.attributes.has("httponly")) {
          findings.push(
            buildFinding(
              ctx.target.url,
              cookie.name,
              "MEDIUM",
              "HttpOnly",
              `Session-like cookie '${cookie.name}' is missing the HttpOnly attribute — it is readable by page JavaScript, so any XSS can exfiltrate it.`,
              "Add the HttpOnly attribute so this cookie cannot be read via document.cookie.",
            ),
          );
        }

        if (!hasStrongSameSite(cookie)) {
          findings.push(
            buildFinding(
              ctx.target.url,
              cookie.name,
              "LOW",
              "SameSite=Lax/Strict",
              `Session-like cookie '${cookie.name}' has no strong SameSite attribute (missing, or set to None) — increasing CSRF exposure.`,
              "Set SameSite=Lax (or Strict where feasible) on this cookie.",
            ),
          );
        }
      }

      return findings;
    } catch {
      return [];
    }
  },
};
