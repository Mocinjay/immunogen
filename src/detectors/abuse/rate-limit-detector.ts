/**
 * rateLimitDetector — RATE-01: an AI endpoint or a login/sign-up endpoint
 * with no rate limiting.
 *
 * An endpoint that calls a paid LLM API on every request lets anyone who
 * finds it run up the bill ("denial of wallet") — a scripted loop against a
 * chat route can burn hundreds of dollars an hour. A login, sign-up, or
 * password-reset endpoint with no limit invites credential stuffing and
 * email/SMS bombing. AI coding tools ship both without a limiter by
 * default.
 *
 * An endpoint file is a server entry point in any supported stack: a
 * Next.js route handler / Pages API route / "use server" module, an
 * Express/Fastify/Hono/Koa file registering routes, a FastAPI/Flask file
 * with route decorators, or a Go file registering routes. It is:
 *   - an AI endpoint when it imports or calls an LLM SDK (OpenAI,
 *     Anthropic, Google Gen AI, the Vercel AI SDK, Groq, Mistral, Cohere,
 *     Replicate, LangChain, LiteLLM, go-openai, ...) — HIGH/MEDIUM;
 *   - a login endpoint when one of its route paths names login / sign-in /
 *     sign-up / register / password reset / OTP / magic link — MEDIUM/MEDIUM.
 *
 * No finding when the file itself applies a limiter, or a global limiter
 * covers every route (Next.js middleware calling a rate limiter,
 * `app.use(rateLimit(...))`, SlowAPI/Flask-Limiter defaults, a Go limiter
 * middleware). When a rate-limit library is installed but nothing in this
 * file or any global middleware uses it, the finding drops to LOW/LOW with
 * a "verify this endpoint is covered" message.
 *
 * Text-only (ENG-05): never evaluates scanned source.
 *
 * No-throw contract (src/core/types.ts Detector.detect): the whole body runs
 * inside a try/catch returning `[]` on any failure.
 */
import { manifestParserFor } from "../../core/ingest/manifests.js";

import type { Detector, DetectorContext, Finding, Severity } from "../../core/types.js";

/** Path segments that suppress every finding in this file (FP allowlist — PITFALLS.md Pitfall 1). */
const FP_ALLOWLIST_SEGMENTS = new Set(["__tests__", "fixtures", "mocks", "examples", "tests", "testdata"]);

/** LLM SDK imports / calls (JS, Python, Go). */
const LLM_USAGE_RE =
  /from\s+["'](?:openai|@anthropic-ai\/sdk|@google\/generative-ai|@google\/genai|ai|@ai-sdk\/[\w-]+|groq-sdk|@mistralai\/mistralai|cohere-ai|replicate|together-ai|@langchain\/[\w-]+|langchain)["']|require\(\s*["'](?:openai|@anthropic-ai\/sdk|groq-sdk|replicate)["']\s*\)|^\s*(?:import|from)\s+(?:openai|anthropic|google\.generativeai|google\.genai|groq|mistralai|cohere|replicate|litellm|langchain\w*)\b|"github\.com\/(?:sashabaranov\/go-openai|anthropics\/anthropic-sdk-go|openai\/openai-go|google\/generative-ai-go)|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com/m;

/** Route-path words that mark an authentication endpoint. */
const AUTH_ENDPOINT_WORD_RE =
  /(?:^|[/_-])(?:login|log-in|signin|sign-in|signup|sign-up|register|forgot-password|reset-password|password-reset|otp|verify-otp|magic-link|send-code|2fa)(?:$|[/_-])/i;

/** A limiter applied in code (JS, Python, Go). */
const RATE_LIMIT_CODE_RE =
  /\brate_?limit|\bRatelimit\b|\bratelimit\.|\blimiter\b|\bLimiter\(|\bthrottle|\bslowDown\(|@\w+\.limit\(|\brate\.NewLimiter\(|tollbooth\.|redis_rate\.|\barcjet\(|\baj\.protect\(/i;

/** A limiter applied globally: middleware or app-level registration. */
const GLOBAL_RATE_LIMIT_RE =
  /\.use\([^)\n]*(?:rate|limit|throttle|slowDown)|\.(?:Use|use)\([^)\n]*(?:limiter|tollbooth|ratelimit)|SlowAPIMiddleware|Limiter\([^)\n]*default_limits|app\.state\.limiter|register\(\s*(?:fastifyRateLimit|rateLimit|require\(\s*["']@fastify\/rate-limit["']\s*\))/i;

/** Rate-limit libraries (npm, PyPI, Go module prefixes). */
const RATE_LIMIT_PACKAGES = [
  "express-rate-limit",
  "rate-limiter-flexible",
  "@upstash/ratelimit",
  "@arcjet/next",
  "@arcjet/node",
  "express-slow-down",
  "@nestjs/throttler",
  "hono-rate-limiter",
  "@fastify/rate-limit",
  "next-rate-limit",
  "slowapi",
  "flask-limiter",
  "fastapi-limiter",
  "django-ratelimit",
  "golang.org/x/time",
  "github.com/ulule/limiter",
  "github.com/didip/tollbooth",
  "github.com/go-redis/redis_rate",
];

/** Next.js middleware basenames (`proxy.ts` is its Next.js 16 name). */
const MIDDLEWARE_BASENAMES = new Set(["middleware.ts", "middleware.js", "proxy.ts", "proxy.js"]);

/** True when `filePath` falls inside a test/fixture directory or is a test file. */
function isAllowlistedPath(filePath: string): boolean {
  const segments = filePath.split("/");
  if (segments.some((segment) => FP_ALLOWLIST_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = segments.at(-1) ?? "";
  return /\.(?:test|spec|stories)\.|^test_.*\.py$|_test\.(?:py|go)$/.test(basename);
}

/** Route paths declared in a non-Next server file (Express/Fastify/Hono/Koa, FastAPI/Flask, Go). */
function declaredRoutePaths(content: string): string[] {
  const paths: string[] = [];
  const patterns = [
    /\.(?:get|post|put|patch|delete|all|route|api_route)\(\s*["'`](\/[^"'`]*)["'`]/g,
    /\.(?:GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\(\s*"[A-Z]*\s?(\/[^"]*)"/g,
    /\burl\s*:\s*["'`](\/[^"'`]*)["'`]/g,
  ];
  for (const pattern of patterns) {
    for (const match of content.matchAll(pattern)) {
      paths.push(match[1] ?? "");
    }
  }
  return paths;
}

/** What makes `ctx.filePath` a server endpoint file, and the route paths it serves; undefined when it is not one. */
function endpointPaths(ctx: DetectorContext): string[] | undefined {
  const path = ctx.filePath;
  const basename = path.split("/").at(-1) ?? "";
  const isNextRoute = /^route\.(?:ts|tsx|js|jsx)$/.test(basename) && path.split("/").includes("app");
  const isPagesApi = /(?:^|\/)pages\/api\//.test(path);
  if (isNextRoute || isPagesApi) {
    return [path];
  }
  if (/^\s*["']use server["']/m.test(ctx.content)) {
    return [path];
  }
  const declared = declaredRoutePaths(ctx.content);
  return declared.length > 0 ? declared : undefined;
}

/** 1-indexed line of the first route registration / handler export in the file (fallback: first line). */
function entryLine(content: string): number {
  const lines = content.split("\n");
  const index = lines.findIndex((line) =>
    /export\s+(?:async\s+function|function|const)\s+(?:GET|POST|PUT|PATCH|DELETE)\b|export\s+default|^\s*@\w+\.(?:get|post|put|patch|delete|route|api_route)\(|\.(?:get|post|put|patch|delete|all|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc)\(\s*["'`]\/|^\s*export\s+async\s+function\s/.test(
      line,
    ),
  );
  return index === -1 ? 1 : index + 1;
}

/** Repo-wide facts, computed per detect() call from the shared fileSet. */
function repoRateLimitFacts(fileSet: ReadonlyMap<string, string>): { globalLimit: boolean; libraryInstalled: boolean } {
  let globalLimit = false;
  let libraryInstalled = false;
  for (const [path, content] of fileSet) {
    const basename = path.split("/").at(-1) ?? "";
    if (MIDDLEWARE_BASENAMES.has(basename) && RATE_LIMIT_CODE_RE.test(content)) {
      globalLimit = true;
    }
    if (/\.(?:[cm]?[jt]sx?|py|go)$/.test(basename) && GLOBAL_RATE_LIMIT_RE.test(content)) {
      globalLimit = true;
    }
    if (basename === "package.json") {
      libraryInstalled ||= RATE_LIMIT_PACKAGES.some((name) => content.includes(`"${name}"`));
    } else {
      const parse = manifestParserFor(path);
      if (parse !== undefined) {
        libraryInstalled ||= parse(content).some((dependency) =>
          RATE_LIMIT_PACKAGES.some((name) => dependency.name === name || dependency.name.startsWith(`${name}/`)),
        );
      }
    }
  }
  return { globalLimit, libraryInstalled };
}

export const rateLimitDetector: Detector = {
  config: {
    name: "rate-limit",
    category: "abuse",
    globs: ["**/*.{ts,tsx,js,jsx,mjs,cjs,py,go}"],
  },

  // Not declared `async`: synchronous text work wrapped in Promise.resolve().
  detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (isAllowlistedPath(ctx.filePath) || RATE_LIMIT_CODE_RE.test(ctx.content)) {
        return Promise.resolve([]);
      }
      const paths = endpointPaths(ctx);
      if (paths === undefined) {
        return Promise.resolve([]);
      }

      const isAiEndpoint = LLM_USAGE_RE.test(ctx.content);
      const authPath = paths.find((path) => AUTH_ENDPOINT_WORD_RE.test(path));
      if (!isAiEndpoint && authPath === undefined) {
        return Promise.resolve([]);
      }

      const { globalLimit, libraryInstalled } = repoRateLimitFacts(ctx.fileSet);
      if (globalLimit) {
        return Promise.resolve([]);
      }

      const line = entryLine(ctx.content);
      const verifyNote = libraryInstalled
        ? " A rate-limit library is installed but not applied here — verify this endpoint is covered."
        : "";
      const findings: Finding[] = [];
      const push = (severity: Severity, message: string, remediation: string): void => {
        findings.push({
          ruleId: "RATE-01",
          category: "abuse",
          detectorName: "rate-limit",
          file: ctx.filePath,
          line,
          severity: libraryInstalled ? "LOW" : severity,
          confidence: libraryInstalled ? "LOW" : "MEDIUM",
          message: `${message}${verifyNote}`,
          remediation,
        });
      };

      if (isAiEndpoint) {
        push(
          "HIGH",
          "AI endpoint calls a paid LLM API with no rate limiting — anyone who finds it can script requests and run up your bill.",
          "Add a per-user / per-IP limit before the LLM call (e.g. @upstash/ratelimit or express-rate-limit; SlowAPI / Flask-Limiter in Python; golang.org/x/time/rate in Go), require a signed-in user, and set a spend cap in the provider dashboard.",
        );
      }
      if (authPath !== undefined) {
        push(
          "MEDIUM",
          `Authentication endpoint (${authPath}) has no rate limiting — open to credential stuffing and email/SMS bombing.`,
          "Limit attempts per IP and per account (e.g. 5 per minute with backoff) using a rate-limit middleware, and lock or challenge after repeated failures.",
        );
      }
      return Promise.resolve(findings);
    } catch {
      // No-throw contract (src/core/types.ts Detector.detect).
      return Promise.resolve([]);
    }
  },
};
