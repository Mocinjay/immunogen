/**
 * lockfiles — resolved dependency versions from package-manager lockfiles.
 *
 * A manifest names ranges (`"next": "^14.0.0"`) and only direct
 * dependencies; the lockfile records the exact version actually installed
 * for every package, transitive ones included — which is where most
 * vulnerable code in an app lives. Supported:
 *
 *   npm   package-lock.json / npm-shrinkwrap.json (lockfileVersion 1-3),
 *         pnpm-lock.yaml (v5, v6, v9), yarn.lock (classic v1 and Berry),
 *         bun.lock (text format)
 *   PyPI  poetry.lock, uv.lock, Pipfile.lock
 *
 * Every parser is a small line/JSON reader with no dependencies, returns
 * each `name@version` once (with the 1-indexed line where it first
 * appears), skips workspace/link/file entries, and returns [] for anything
 * it cannot read rather than throwing.
 *
 * Text-only (ENG-05): never evaluates scanned content.
 */
import { normalizePythonName, type Ecosystem } from "./manifests.js";

/** One resolved package from a lockfile. */
export interface LockedPackage {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** 1-indexed line of the package's entry in the lockfile. */
  line: number;
  /** True when the lockfile marks the package as installed only for development (npm's `"dev": true`). */
  dev?: boolean;
}

/** Lockfile basenames, by the ecosystem they resolve. */
export const NPM_LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"];
export const PYTHON_LOCKFILES = ["poetry.lock", "uv.lock", "Pipfile.lock"];

/** A plain semver-ish version (excludes `link:`, `file:`, `workspace:`, git URLs, tarball paths). */
const EXACT_VERSION_RE = /^\d+\.\d+[\w.+-]*$/;

/** Collects unique name@version entries in first-seen order. */
class PackageSet {
  private readonly seen = new Set<string>();
  readonly packages: LockedPackage[] = [];

  add(ecosystem: Ecosystem, name: string, version: string, line: number, dev = false): void {
    const key = `${name}@${version}`;
    if (name === "" || !EXACT_VERSION_RE.test(version) || this.seen.has(key)) {
      return;
    }
    this.seen.add(key);
    this.packages.push({ ecosystem, name, version, line, ...(dev ? { dev: true } : {}) });
  }
}

/**
 * Index of JSON object keys to the 1-indexed line they open on (first
 * occurrence), built in one pass — lockfiles run to tens of thousands of
 * lines, so per-entry line searches would be quadratic.
 */
function objectKeyLines(lines: string[]): Map<string, number> {
  const keyLines = new Map<string, number>();
  for (const [index, line] of lines.entries()) {
    const key = line.match(/^\s*"([^"]+)":\s*\{/)?.[1];
    if (key !== undefined && !keyLines.has(key)) {
      keyLines.set(key, index + 1);
    }
  }
  return keyLines;
}

/** npm package-lock.json / npm-shrinkwrap.json (lockfileVersion 1, 2, 3). */
export function parsePackageLock(content: string): LockedPackage[] {
  const set = new PackageSet();
  const keyLines = objectKeyLines(content.split("\n"));
  let parsed: { packages?: Record<string, unknown>; dependencies?: Record<string, unknown> };
  try {
    parsed = JSON.parse(content) as typeof parsed;
  } catch {
    return [];
  }

  if (parsed.packages !== undefined && typeof parsed.packages === "object") {
    // v2/v3: keys are install paths ("node_modules/a/node_modules/@s/b").
    for (const [path, value] of Object.entries(parsed.packages)) {
      const entry = value as { version?: unknown; link?: unknown; name?: unknown; dev?: unknown };
      const marker = path.lastIndexOf("node_modules/");
      if (marker === -1 || entry.link === true || typeof entry.version !== "string") {
        continue;
      }
      const name = typeof entry.name === "string" ? entry.name : path.slice(marker + "node_modules/".length);
      set.add("npm", name, entry.version, keyLines.get(path) ?? 1, entry.dev === true);
    }
    return set.packages;
  }

  // v1: nested `dependencies` trees.
  const walk = (dependencies: Record<string, unknown>): void => {
    for (const [name, value] of Object.entries(dependencies)) {
      const entry = value as { version?: unknown; dependencies?: unknown; dev?: unknown };
      if (typeof entry.version === "string") {
        set.add("npm", name, entry.version, keyLines.get(name) ?? 1, entry.dev === true);
      }
      if (typeof entry.dependencies === "object" && entry.dependencies !== null) {
        walk(entry.dependencies as Record<string, unknown>);
      }
    }
  };
  if (parsed.dependencies !== undefined && typeof parsed.dependencies === "object") {
    walk(parsed.dependencies);
  }
  return set.packages;
}

/** Splits an npm `name@version` specifier, keeping a leading scope `@`. */
function splitNameAtVersion(spec: string): [string, string] | undefined {
  const at = spec.indexOf("@", 1);
  return at === -1 ? undefined : [spec.slice(0, at), spec.slice(at + 1)];
}

/** pnpm-lock.yaml: `packages:` (and v9 `snapshots:`) keys — `/name@1.2.3`, `name@1.2.3(peer@x)`, or v5 `/name/1.2.3`. */
/** Strips quotes, a leading `/` and any `(peer@x)` suffix from a pnpm lockfile key or version. */
function pnpmClean(raw: string): string {
  return raw.trim().replace(/^['"]|['"]$/g, "").replace(/^\//, "").replace(/\(.*$/, "");
}

/**
 * Packages a pnpm v6/v9 lockfile installs ONLY for development: everything
 * not reachable from any importer's `dependencies` / `optionalDependencies`
 * through the `snapshots` (v9) or `packages` (v6) dependency graph.
 * Returns `undefined` when the lockfile has no importer roots to start
 * from (then nothing is marked dev, rather than guessing).
 */
export function pnpmDevOnlyPackages(content: string): Set<string> | undefined {
  const roots: string[] = [];
  const edges = new Map<string, string[]>();
  const all = new Set<string>();
  let section = "";
  let importerGroup = "";
  let pendingName: string | undefined;
  let entry: string | undefined;
  let inDeps = false;

  for (const line of content.split("\n")) {
    if (/^\S/.test(line)) {
      section = line.replace(/:.*$/, "");
      continue;
    }
    const indent = line.length - line.trimStart().length;
    const text = line.trim();
    if (text === "") {
      continue;
    }
    if (section === "importers") {
      if (indent === 4) {
        importerGroup = text.replace(/:$/, "");
      } else if (indent === 6 && (importerGroup === "dependencies" || importerGroup === "optionalDependencies")) {
        pendingName = pnpmClean(text.replace(/:$/, ""));
      } else if (indent === 8 && pendingName !== undefined && text.startsWith("version:")) {
        const version = pnpmClean(text.slice("version:".length));
        if (/^\d/.test(version)) {
          roots.push(`${pendingName}@${version}`);
        }
      }
    } else if (section === "snapshots" || section === "packages") {
      if (indent === 2) {
        entry = pnpmClean(text.replace(/:\s*\{\}$/, "").replace(/:$/, ""));
        all.add(entry);
        inDeps = false;
      } else if (indent === 4) {
        inDeps = text === "dependencies:" || text === "optionalDependencies:";
      } else if (indent === 6 && inDeps && entry !== undefined) {
        const colon = text.lastIndexOf(": ");
        if (colon > 0) {
          const target = `${pnpmClean(text.slice(0, colon))}@${pnpmClean(text.slice(colon + 2))}`;
          const list = edges.get(entry) ?? [];
          list.push(target);
          edges.set(entry, list);
        }
      }
    }
  }
  if (roots.length === 0) {
    return undefined;
  }
  const reachable = new Set<string>();
  const queue = [...roots];
  for (let next = queue.pop(); next !== undefined; next = queue.pop()) {
    if (reachable.has(next)) {
      continue;
    }
    reachable.add(next);
    queue.push(...(edges.get(next) ?? []));
  }
  return new Set([...all].filter((key) => !reachable.has(key)));
}

export function parsePnpmLock(content: string): LockedPackage[] {
  const set = new PackageSet();
  const devOnly = pnpmDevOnlyPackages(content);
  let inPackages = false;
  for (const [index, line] of content.split("\n").entries()) {
    if (/^\S/.test(line)) {
      inPackages = line.startsWith("packages:") || line.startsWith("snapshots:");
      continue;
    }
    if (!inPackages || !/^ {2}\S/.test(line)) {
      continue;
    }
    const key = line.trim().replace(/:$/, "").replace(/^['"]|['"]$/g, "").replace(/^\//, "");
    // pnpm v5 keys are name/version[_peer@x] (scoped: @scope/name/version).
    const nameEnd = key.startsWith("@") ? key.indexOf("/", key.indexOf("/") + 1) : key.indexOf("/");
    if (nameEnd > 0 && /^\d/.test(key.slice(nameEnd + 1))) {
      set.add("npm", key.slice(0, nameEnd), key.slice(nameEnd + 1).replace(/_.*$/, ""), index + 1);
      continue;
    }
    // pnpm v6/v9 keys are name@version[(peer@x)].
    const split = splitNameAtVersion(key.replace(/\(.*$/, ""));
    if (split !== undefined) {
      set.add("npm", split[0], split[1], index + 1, devOnly?.has(`${split[0]}@${split[1]}`) === true);
    }
  }
  return set.packages;
}

/** yarn.lock: classic v1 (`version "1.2.3"`) and Berry (`version: 1.2.3`). */
export function parseYarnLock(content: string): LockedPackage[] {
  const set = new PackageSet();
  let currentName: string | undefined;
  let headerLine = 0;
  for (const [index, line] of content.split("\n").entries()) {
    if (/^\S/.test(line) && line.trimEnd().endsWith(":") && !line.startsWith("#") && !line.startsWith("__metadata")) {
      const firstSpec = line.split(",")[0]?.trim().replace(/^"|"$/g, "").replace(/:$/, "").replace(/"$/, "") ?? "";
      // Berry workspace / link / portal / file entries are the project's own code.
      currentName = /@(?:workspace|link|portal|file):/.test(firstSpec) ? undefined : splitNameAtVersion(firstSpec)?.[0];
      headerLine = index + 1;
      continue;
    }
    const version = line.match(/^\s+version:?\s+"?([^"\s]+)"?\s*$/)?.[1];
    if (currentName !== undefined && version !== undefined) {
      set.add("npm", currentName, version, headerLine);
      currentName = undefined;
    }
  }
  return set.packages;
}

/** bun.lock (text JSONC): `"key": ["name@version", ...]` entries under `packages`. */
export function parseBunLock(content: string): LockedPackage[] {
  const set = new PackageSet();
  for (const [index, line] of content.split("\n").entries()) {
    const spec = line.match(/^\s*"[^"]+":\s*\[\s*"([^"]+)"/)?.[1];
    const split = spec === undefined ? undefined : splitNameAtVersion(spec);
    if (split !== undefined) {
      set.add("npm", split[0], split[1], index + 1);
    }
  }
  return set.packages;
}

/** poetry.lock / uv.lock: `[[package]]` tables with `name = "..."` and `version = "..."`. */
export function parsePythonTomlLock(content: string): LockedPackage[] {
  const set = new PackageSet();
  let name: string | undefined;
  let nameLine = 0;
  for (const [index, line] of content.split("\n").entries()) {
    if (line.trim() === "[[package]]") {
      name = undefined;
      continue;
    }
    const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nameMatch !== null) {
      name = normalizePythonName(nameMatch[1] ?? "");
      nameLine = index + 1;
      continue;
    }
    const version = line.match(/^version\s*=\s*"([^"]+)"/)?.[1];
    if (name !== undefined && version !== undefined) {
      set.add("PyPI", name, version, nameLine);
      name = undefined;
    }
  }
  return set.packages;
}

/** Pipfile.lock: JSON `default` / `develop` maps of `{ version: "==1.2.3" }`. */
export function parsePipfileLock(content: string): LockedPackage[] {
  const set = new PackageSet();
  const keyLines = objectKeyLines(content.split("\n"));
  let parsed: { default?: Record<string, unknown>; develop?: Record<string, unknown> };
  try {
    parsed = JSON.parse(content) as typeof parsed;
  } catch {
    return [];
  }
  for (const group of [parsed.default, parsed.develop]) {
    for (const [name, value] of Object.entries(group ?? {})) {
      const version = (value as { version?: unknown }).version;
      if (typeof version === "string") {
        set.add("PyPI", normalizePythonName(name), version.replace(/^==/, ""), keyLines.get(name) ?? 1);
      }
    }
  }
  return set.packages;
}

/** Lockfile parser by basename. */
export function lockfileParserFor(filePath: string): ((content: string) => LockedPackage[]) | undefined {
  const basename = filePath.split("/").at(-1) ?? "";
  switch (basename) {
    case "package-lock.json":
    case "npm-shrinkwrap.json":
      return parsePackageLock;
    case "pnpm-lock.yaml":
      return parsePnpmLock;
    case "yarn.lock":
      return parseYarnLock;
    case "bun.lock":
      return parseBunLock;
    case "poetry.lock":
    case "uv.lock":
      return parsePythonTomlLock;
    case "Pipfile.lock":
      return parsePipfileLock;
    default:
      return undefined;
  }
}
