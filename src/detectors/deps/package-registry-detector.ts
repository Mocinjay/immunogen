/**
 * packageRegistryDetector — DEP-02: dependencies that do not exist.
 *
 * AI coding agents regularly invent plausible package names ("slopsquatting"
 * targets): `npm install` / `pip install` then fails — or, once someone
 * registers the name, quietly installs and runs whatever they published.
 * For every DIRECT dependency declared in `package.json`,
 * `requirements*.txt`, `pyproject.toml` or `Pipfile`, this asks the public
 * registry whether the name exists (`HEAD registry.npmjs.org/<name>`,
 * `HEAD pypi.org/pypi/<name>/json`). A 404 is a HIGH finding.
 *
 * False-positive controls — a package served by a private registry is not
 * on the public one, so the check is skipped for:
 *   - workspace packages (any `name` declared by a package.json in the repo);
 *   - non-registry specifiers (`workspace:`, `file:`, `link:`, git / URL);
 *   - scoped npm packages whose scope an `.npmrc` / `.yarnrc.yml` maps to a
 *     registry, and every npm package when one sets a non-npmjs default;
 *   - Python manifests that name another index (`--index-url`,
 *     `--extra-index-url`, `[[tool.poetry.source]]`, `[[tool.uv.index]]`,
 *     a Pipfile `[[source]]` that is not pypi.org).
 * Confidence is MEDIUM for that reason.
 *
 * Network: only package NAMES are sent (the OSV check already sends names
 * and versions); `--offline` skips this detector's requests entirely.
 * Unreachable registries yield no findings, never a guess. Results are
 * cached per process.
 */
import { fetchWithRetry } from "./http.js";
import { manifestParserFor } from "../../core/ingest/manifests.js";
import { isTestOrFixturePath } from "../shared/test-paths.js";

import type { Detector, DetectorContext, Finding } from "../../core/types.js";

/** Concurrent registry lookups per manifest. */
const CONCURRENCY = 8;

/** Most dependencies checked per manifest. */
const MAX_PER_MANIFEST = 200;

/** Per-attempt timeout for one registry lookup. */
const LOOKUP_TIMEOUT_MS = 8_000;

/** Specifiers that do not come from the npm registry. */
// eslint-disable-next-line security/detect-unsafe-regex -- anchored, single-run classes around one literal; benchmarked linear on 100k-char adversarial input
const NON_REGISTRY_SPEC_RE = /^(?:workspace:|file:|link:|portal:|patch:|git\+|git:|github:|gitlab:|bitbucket:|https?:|\.{0,2}\/)|^[\w.-]+\/[\w.-]+(?:#.*)?$/;

/** A plausible npm package name (scoped or not). */
// eslint-disable-next-line security/detect-unsafe-regex -- anchored, single-run classes around one literal; benchmarked linear on 100k-char adversarial input
const NPM_NAME_RE = /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i;

/** A plausible PyPI project name. */
const PYPI_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** `exists` per `ecosystem:name`; absent = not looked up or lookup failed. */
const existsCache = new Map<string, boolean>();

/** One declared dependency to check. */
interface Declared {
  ecosystem: "npm" | "PyPI";
  name: string;
  line: number;
}

/** 1-indexed line where `"name"` first appears as a JSON key (1 when absent). */
function jsonKeyLine(content: string, name: string): number {
  const index = content.split("\n").findIndex((line) => line.includes(`"${name}"`));
  return index === -1 ? 1 : index + 1;
}

/** Every package `name` declared anywhere in the repo — local workspace packages, never on a registry by necessity. */
function workspaceNames(fileSet: ReadonlyMap<string, string>): Set<string> {
  const names = new Set<string>();
  for (const [path, content] of fileSet) {
    if (path === "package.json" || path.endsWith("/package.json")) {
      try {
        const name = (JSON.parse(content) as { name?: unknown }).name;
        if (typeof name === "string") {
          names.add(name);
        }
      } catch {
        // Malformed manifest: contributes no name.
      }
    }
  }
  return names;
}

/** Hosts of the public npm registry (and Yarn's mirror of it). */
const PUBLIC_NPM_REGISTRY_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);

/** True when `url` points at the public npm registry — by exact hostname, never by substring. */
function isPublicNpmRegistry(url: string): boolean {
  try {
    return PUBLIC_NPM_REGISTRY_HOSTS.has(new URL(url).hostname.toLowerCase());
  } catch {
    return false; // Not a URL: treat as a private / unknown registry and check nothing.
  }
}

/** What the repo's npm client configs say about private registries. */
function npmRegistryConfig(fileSet: ReadonlyMap<string, string>): { privateDefault: boolean; privateScopes: Set<string> } {
  const privateScopes = new Set<string>();
  let privateDefault = false;
  for (const [path, content] of fileSet) {
    const basename = path.slice(path.lastIndexOf("/") + 1);
    if (basename !== ".npmrc" && basename !== ".yarnrc.yml" && basename !== ".yarnrc" && basename !== "bunfig.toml") {
      continue;
    }
    for (const match of content.matchAll(/(@[\w.-]+):registry/g)) {
      privateScopes.add(match[1] ?? "");
    }
    for (const match of content.matchAll(/^\s*["']?(@[\w.-]+)["']?\s*:\s*$/gm)) {
      privateScopes.add(match[1] ?? ""); // .yarnrc.yml npmScopes: { "@acme": ... }
    }
    const defaultRegistry = content.match(/^\s*(?:registry|npmRegistryServer)\s*[=:]\s*["']?(\S+?)["']?\s*$/m)?.[1];
    if (defaultRegistry !== undefined && !isPublicNpmRegistry(defaultRegistry)) {
      privateDefault = true;
    }
  }
  return { privateDefault, privateScopes };
}

/** True when a Python manifest points at a package index other than PyPI. */
function usesPrivatePythonIndex(filePath: string, content: string): boolean {
  if (/(?:^|\s)(?:--index-url|--extra-index-url|-i)\s+\S/m.test(content)) {
    return true;
  }
  if (/^\s*\[\[tool\.(?:poetry\.source|uv\.index|pdm\.source)\]\]/m.test(content)) {
    return true;
  }
  return filePath.endsWith("Pipfile") && /^\s*url\s*=\s*["'](?!https:\/\/pypi\.org)/m.test(content);
}

/** The dependencies in one manifest worth checking (see the module comment). */
function declaredDependencies(ctx: DetectorContext): Declared[] {
  const path = ctx.filePath;
  if (path === "package.json" || path.endsWith("/package.json")) {
    const registry = npmRegistryConfig(ctx.fileSet);
    if (registry.privateDefault) {
      return [];
    }
    const workspace = workspaceNames(ctx.fileSet);
    let parsed: { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> };
    try {
      parsed = JSON.parse(ctx.content) as typeof parsed;
    } catch {
      return [];
    }
    const declared: Declared[] = [];
    for (const [key, spec] of Object.entries({ ...parsed.dependencies, ...parsed.devDependencies })) {
      if (typeof spec !== "string") {
        continue;
      }
      const alias = spec.startsWith("npm:") ? spec.slice(4).replace(/(.)@.*$/, "$1") : undefined;
      const name = alias ?? key;
      const scope = name.startsWith("@") ? name.slice(0, name.indexOf("/")) : undefined;
      if (
        (alias === undefined && NON_REGISTRY_SPEC_RE.test(spec.trim())) ||
        !NPM_NAME_RE.test(name) ||
        workspace.has(name) ||
        (scope !== undefined && registry.privateScopes.has(scope))
      ) {
        continue;
      }
      declared.push({ ecosystem: "npm", name, line: jsonKeyLine(ctx.content, key) });
    }
    return declared;
  }

  const parse = manifestParserFor(path);
  if (parse === undefined || usesPrivatePythonIndex(path, ctx.content)) {
    return [];
  }
  return parse(ctx.content)
    .filter((dependency) => dependency.ecosystem === "PyPI" && PYPI_NAME_RE.test(dependency.name))
    .map((dependency) => ({ ecosystem: "PyPI" as const, name: dependency.name, line: dependency.line }));
}

/** Registry URL that answers 404 for a name that does not exist. */
function registryUrl(dependency: Declared): string {
  return dependency.ecosystem === "npm"
    ? `https://registry.npmjs.org/${dependency.name.replaceAll("/", "%2f")}`
    : `https://pypi.org/pypi/${encodeURIComponent(dependency.name)}/json`;
}

/** `true` / `false` when the registry answered clearly, `undefined` otherwise. */
async function exists(dependency: Declared): Promise<boolean | undefined> {
  const key = `${dependency.ecosystem}:${dependency.name.toLowerCase()}`;
  const cached = existsCache.get(key);
  if (cached !== undefined) {
    return cached;
  }
  try {
    const response = await fetchWithRetry(registryUrl(dependency), { method: "HEAD" }, LOOKUP_TIMEOUT_MS);
    await response.body?.cancel().catch(() => undefined);
    const answer = response.status === 404 ? false : response.ok ? true : undefined;
    if (answer !== undefined) {
      existsCache.set(key, answer);
    }
    return answer;
  } catch {
    return undefined;
  }
}

export const packageRegistryDetector: Detector = {
  config: {
    name: "package-registry",
    category: "deps",
    globs: ["package.json", "**/package.json", "**/requirements*.txt", "**/pyproject.toml", "**/Pipfile"],
    requiresNetwork: true,
  },

  async detect(ctx: DetectorContext): Promise<Finding[]> {
    try {
      if (ctx.offline === true || isTestOrFixturePath(ctx.filePath)) {
        return [];
      }
      const queue = declaredDependencies(ctx).slice(0, MAX_PER_MANIFEST);
      const missing: Declared[] = [];
      const worker = async (): Promise<void> => {
        for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
          if ((await exists(next)) === false) {
            missing.push(next);
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));

      return missing
        .sort((left, right) => left.line - right.line)
        .map((dependency) => ({
          ruleId: "DEP-02",
          category: "deps" as const,
          detectorName: "package-registry",
          file: ctx.filePath,
          line: dependency.line,
          severity: "HIGH" as const,
          confidence: "MEDIUM" as const,
          message: `Dependency "${dependency.name}" does not exist on the public ${dependency.ecosystem === "npm" ? "npm registry" : "PyPI index"} — unless it comes from a private registry, it is probably a hallucinated name, and anyone can publish a package under it that your next install would run.`,
          remediation: `Check what ${dependency.name} was meant to be and replace it with the real package (or remove it). If it does come from a private registry, configure that registry in ${dependency.ecosystem === "npm" ? ".npmrc" : "your index settings"} so installs never fall back to the public one.`,
          matchedText: dependency.name,
        }));
    } catch {
      return [];
    }
  },
};
