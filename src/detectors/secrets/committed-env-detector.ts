/**
 * committedEnvDetector — text-only CAT-1 (Leaked Secrets) detector, SEC-05.
 *
 * The finding is about a committed env file (`.env`, `.env.local`,
 * `.env.production`, `.env.staging` present in the tree and not ignored),
 * rated by what it holds. Each `NAME=value` line is classified:
 *   - secret: a secret-named variable (`*_SECRET`, `*_KEY`, `*_TOKEN`,
 *     `*PASSWORD*`, `DATABASE_URL`, ...) with a real-looking value, a value
 *     shaped like a provider key, or a connection URL with a password for a
 *     remote host;
 *   - not secret: client-public variables (`NEXT_PUBLIC_`, `VITE_`, ...,
 *     unless named SECRET / PRIVATE / PASSWORD / SERVICE_ROLE — BUNDLE-01
 *     reports those), public-by-design keys (publishable / anon / site
 *     keys), plain URLs, numbers, flags, placeholders and empty values.
 * Any secret value makes the file CRITICAL. Without one, the file is INFO —
 * Next.js and Vite document committing `.env` / `.env.production` defaults —
 * or LOW for a `.env*.local` file, which those frameworks reserve for
 * untracked machine-local values. Only variable NAMES are reported, never
 * values.
 *
 * Two guards run in sequence before a Finding is ever pushed:
 *   1. FP allowlist — test/fixture/mock/example directories never fire
 *.
 *   2. Template exclusion — `.env.example`/`.env.sample`/etc. carry no real
 *      secrets by convention and are excluded outright.
 *
 * Whether the file is committed is decided upstream by the file walker
 * (src/core/ingest/file-walker.ts): an env file only reaches this detector
 * when git tracks it, or when no `.gitignore` (root or nested) excludes it.
 * Re-checking `.gitignore` here would wrongly hide a `.env` that was
 * committed first and gitignored later — it is still in the repo.
 *
 * No-throw contract (src/core/types.ts `Detector.detect`): the entire body
 * runs inside try/catch returning `[]` on any failure.
 *
 * ENG-05 (text-only invariant): reads `ctx.filePath` and `ctx.fileSet`
 * string values only; never reads `ctx.ast`, never imports a parser, and
 * never evaluates, requires, or spawns a subprocess from scanned content.
 *
 * No `matchedText` is set on the pushed Finding — values are never echoed;
 * the message names the secret variables instead.
 */
import {
  CONNECTION_URL_RE,
  isLocalHost,
  isPlaceholderPassword,
  isPlaceholderSecret,
  PLACEHOLDER_VALUE_RE,
  PROVIDER_KEY_PATTERNS,
} from "./secret-patterns.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";
import { isInTestDirectory } from "../shared/test-paths.js";

/** A leading `export ` keyword, stripped before ENV_LINE_RE runs. */
const EXPORT_PREFIX_RE = /^\s*export\s+/;

/** `NAME=value` (value may be quoted, may carry a trailing comment). */
const ENV_LINE_RE = /^\s*([A-Za-z_][\w.-]*)\s*=(.*)$/;

/** Variable-name fragments that mark a value as sensitive. */
const SECRET_NAME_RE = /SECRET|KEY|TOKEN|PASSWORD|PASSWD|PWD|PRIVATE|CREDENTIAL|AUTH|DSN|SERVICE_ROLE|DATABASE_URL|DB_URL|CONNECTION|_URI$/i;

/** Client-bundle prefixes: the framework inlines these into public code by design. */
const CLIENT_PUBLIC_PREFIX_RE = /^(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)/i;

/** Name fragments that are never public, even behind a client prefix. */
const NEVER_PUBLIC_RE = /SECRET|PRIVATE|PASSWORD|SERVICE_ROLE/i;

/** Keys documented by their provider as safe to ship to clients. */
const PUBLIC_BY_DESIGN_RE = /PUBLISHABLE|ANON_KEY|SITE_?KEY|PUBLIC_KEY|MEASUREMENT_ID/i;

/** Values below this length are flags, ports or stubs, not credentials. */
const MIN_SECRET_VALUE_LENGTH = 6;

/** Most secret variable names listed in the message before the rest are counted. */
const MAX_NAMED = 5;

/** Strips surrounding quotes, or an unquoted value's trailing ` # comment`. */
function unquote(raw: string): string {
  const trimmed = raw.trim();
  const quoted = trimmed.match(/^(['"`])(.*)\1/);
  if (quoted !== null) {
    return quoted[2] ?? "";
  }
  return trimmed.replace(/\s+#.*$/, "").trim();
}

/** True when `value` contains a provider-key shape or a remote connection URL with a real password. */
function looksLikeCredential(value: string): boolean {
  // Google `AIza` keys are public by design for Maps / Firebase; the secrets
  // detector judges them with surrounding context instead.
  const keyPatterns = PROVIDER_KEY_PATTERNS.filter((pattern) => pattern.provider !== "Google");
  if (keyPatterns.some(({ regex }) => [...value.matchAll(regex)].some((match) => !isPlaceholderSecret(match[0])))) {
    return true;
  }
  return [...value.matchAll(CONNECTION_URL_RE)].some(
    (match) => !isLocalHost(match[4] ?? "") && !isPlaceholderPassword(match[3] ?? ""),
  );
}

/** True when `NAME=value` holds a secret (see the module comment for the rules). */
function isSecretEntry(name: string, value: string): boolean {
  if (looksLikeCredential(value)) {
    return true;
  }
  const clientPublic = CLIENT_PUBLIC_PREFIX_RE.test(name) && !NEVER_PUBLIC_RE.test(name);
  if (!SECRET_NAME_RE.test(name) || clientPublic || PUBLIC_BY_DESIGN_RE.test(name)) {
    return false;
  }
  if (
    value.length < MIN_SECRET_VALUE_LENGTH ||
    value.includes("${") ||
    /^(?:true|false|\d+)$/i.test(value) ||
    PLACEHOLDER_VALUE_RE.test(value) ||
    isPlaceholderSecret(value)
  ) {
    return false;
  }
  // A URL is an endpoint; one carrying a real remote password was already
  // caught by looksLikeCredential above.
  return !/^[a-z][\w+.-]*:\/\//i.test(value);
}

/** Every secret-holding variable in an env file, with the 1-indexed line it is on. */
function secretEntries(content: string): Array<{ name: string; line: number }> {
  const entries: Array<{ name: string; line: number }> = [];
  for (const [index, line] of content.split("\n").entries()) {
    const match = line.replace(EXPORT_PREFIX_RE, "").match(ENV_LINE_RE);
    const name = match?.[1];
    if (name === undefined || match === null) {
      continue;
    }
    if (isSecretEntry(name, unquote(match[2] ?? ""))) {
      entries.push({ name, line: index + 1 });
    }
  }
  return entries;
}

/**
 * Template-suffix basenames that carry no real secrets by convention and
 * must never be flagged, even though their basename otherwise matches the
 * ".env or .env.-prefixed" rule below.
 */
const TEMPLATE_BASENAMES = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
  ".env.dist",
  ".env.local.example",
]);

/**
 * Returns the basename of a repo-relative path (the text after the final
 * `/`, or the whole string if there is no `/`). Mirrors the exact rule the
 * walker's own stack detector uses (src/core/ingest/stack-detector.ts
 * `hasEnvFile`) so "is an env file" stays defined identically across both
 * call sites.
 */
function basenameOf(filePath: string): string {
  return filePath.slice(filePath.lastIndexOf("/") + 1);
}

/** True when `basename` is `.env` or starts with `.env.`, per the walker's own env-file rule. */
function isEnvBasename(basename: string): boolean {
  return basename === ".env" || basename.startsWith(".env.");
}

export const committedEnvDetector: Detector = {
  config: {
    name: "committed-env",
    category: "secrets",
    globs: ["**/.env*"],
  },

  // Not declared `async` — no network/disk wait; the body is plain
  // synchronous work wrapped in `Promise.resolve()`, matching the same
  // sync-detector convention documented in entropy-detector.ts.
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isInTestDirectory(ctx.filePath)) {
        return Promise.resolve([]);
      }

      const basename = basenameOf(ctx.filePath);
      if (!isEnvBasename(basename)) {
        // Should not happen given config.globs, but the no-throw contract
        // means this path must still resolve cleanly rather than assume.
        return Promise.resolve([]);
      }
      if (TEMPLATE_BASENAMES.has(basename)) {
        return Promise.resolve([]);
      }

      const secrets = secretEntries(ctx.content);
      if (secrets.length > 0) {
        const names = secrets.slice(0, MAX_NAMED).map((entry) => entry.name).join(", ");
        const more = secrets.length > MAX_NAMED ? ` and ${String(secrets.length - MAX_NAMED)} more` : "";
        return Promise.resolve([
          {
            ruleId: "SEC-05",
            category: "secrets",
            detectorName: "committed-env",
            file: ctx.filePath,
            line: secrets[0]?.line ?? 1,
            severity: "CRITICAL",
            confidence: "HIGH",
            message: `Committed environment file (${ctx.filePath}) contains secret values: ${names}${more}.`,
            remediation:
              "Add this file to .gitignore, remove it from git history (e.g. git filter-repo or BFG), and rotate every secret it contained — committing it once is enough to leak everything inside.",
          },
        ]);
      }

      const isLocal = basename.endsWith(".local");
      return Promise.resolve([
        {
          ruleId: "SEC-05",
          category: "secrets",
          detectorName: "committed-env",
          file: ctx.filePath,
          line: 1,
          severity: isLocal ? "LOW" : "INFO",
          confidence: "HIGH",
          message: isLocal
            ? `Committed ${basename} file — no secret values found in it, but .local env files are meant to stay on one machine and out of git.`
            : `Committed environment file (${ctx.filePath}) with no secret-looking values — committing framework defaults is fine, as long as real secrets stay in an untracked .env*.local.`,
          remediation: isLocal
            ? `Add ${basename} to .gitignore and remove it from the repository (git rm --cached ${ctx.filePath}).`
            : "Keep secrets in an untracked .env.local (or your host's secret settings) and only public, non-sensitive defaults in this file.",
        },
      ]);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect): any
      // unexpected failure must resolve to [], never reject.
      return Promise.resolve([]);
    }
  },
};
