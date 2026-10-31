/**
 * manifests — dependency parsing for Python and Go projects.
 *
 * The JavaScript side reads `package.json` with `JSON.parse`; Python and Go
 * manifests are line-oriented text formats, parsed here with small,
 * dependency-free readers (no TOML library — only the handful of shapes
 * dependency declarations actually take):
 *
 *   - `requirements*.txt`: `name==1.2.3`, `name[extra]>=1.0 ; markers`
 *   - `pyproject.toml`: PEP 621 `dependencies = [...]` (and optional-
 *     dependency groups), Poetry `[tool.poetry.dependencies]` tables
 *   - `Pipfile`: `[packages]` / `[dev-packages]` tables
 *   - `go.mod`: `require` lines and blocks
 *
 * Each dependency carries an exact `version` only when the manifest pins
 * one (`==1.2.3`, a bare Poetry/Pipfile version, any go.mod requirement) —
 * ranges cannot be vulnerability-checked and are left undefined. Python
 * names are normalized per PEP 503 (lowercase, `_`/`.` -> `-`).
 *
 * Text-only (ENG-05): never evaluates scanned content.
 */

/** OSV.dev ecosystem name for each manifest family. */
export type Ecosystem = "npm" | "PyPI" | "Go";

/** One declared dependency, with its manifest line. */
export interface ManifestDependency {
  ecosystem: Ecosystem;
  name: string;
  /** The specifier as written (for messages). */
  rawVersion: string;
  /** Exact pinned version, or undefined when the manifest gives a range. */
  version: string | undefined;
  /** 1-indexed manifest line of the declaration. */
  line: number;
}

/** PEP 503 name normalization. */
export function normalizePythonName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

/** A PEP 508 requirement string (extras already removed): name, then the version spec up to any marker/comment. */
const PEP508_RE = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*([^;#]*)/;

/** Parses one PEP 508 requirement string into a dependency (exact version only for a single `==`/`===` pin). */
function parsePep508(requirement: string, line: number): ManifestDependency | undefined {
  const match = requirement.replace(/\[[^\]]*\]/, "").match(PEP508_RE);
  const name = match?.[1];
  if (name === undefined) {
    return undefined;
  }
  const spec = (match?.[2] ?? "").trim();
  const pinned = spec.match(/^={2,3}\s*([0-9][\w.+!-]*)$/);
  return { ecosystem: "PyPI", name: normalizePythonName(name), rawVersion: spec, version: pinned?.[1], line };
}

/** Parses a `requirements.txt` (skipping comments, `-r`/`-e`/option lines, and URLs). */
export function parseRequirementsTxt(content: string): ManifestDependency[] {
  const dependencies: ManifestDependency[] = [];
  for (const [index, rawLine] of content.split("\n").entries()) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (line === "" || line.startsWith("#") || line.startsWith("-") || line.includes("://")) {
      continue;
    }
    const dependency = parsePep508(line, index + 1);
    if (dependency !== undefined) {
      dependencies.push(dependency);
    }
  }
  return dependencies;
}

/** Version string of a Poetry/Pipfile table entry: `"1.2.3"`, `"^1.2"`, or `{ version = "1.2.3", ... }`. */
function tableEntryVersion(value: string): string | undefined {
  const inline = value.match(/version\s*=\s*["']([^"']*)["']/);
  if (inline !== null) {
    return inline[1];
  }
  return value.match(/^\s*["']([^"']*)["']/)?.[1];
}

/** Exact version from a Poetry/Pipfile specifier: a bare version or `==x`; ranges/wildcards yield undefined. */
function exactFromTableSpec(spec: string): string | undefined {
  const version = spec.trim().replace(/^={2,3}\s*/, "");
  return /^[0-9][\w.+!-]*$/.test(version) ? version : undefined;
}

/** Section headers whose `name = spec` lines are dependency declarations. */
const DEPENDENCY_TABLE_RE = /^\[(?:tool\.poetry\.(?:dev-)?dependencies|tool\.poetry\.group\.[\w-]+\.dependencies|packages|dev-packages)\]$/;

/** Parses `pyproject.toml` (PEP 621 + Poetry) or a `Pipfile`. */
export function parsePyprojectOrPipfile(content: string): ManifestDependency[] {
  const dependencies: ManifestDependency[] = [];
  let section = "";
  let inDependencyArray = false;

  for (const [index, rawLine] of content.split("\n").entries()) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    const header = line.match(/^\[[^\]]+\]$/);
    if (header !== null) {
      section = line;
      inDependencyArray = false;
      continue;
    }

    const opensArray =
      (section === "[project]" && /^dependencies\s*=\s*\[/.test(line)) ||
      (section === "[project.optional-dependencies]" && /^[\w-]+\s*=\s*\[/.test(line));
    if (opensArray || inDependencyArray) {
      const body = opensArray ? line.slice(line.indexOf("[") + 1) : line;
      for (const quoted of body.matchAll(/["']([^"']+)["']/g)) {
        const dependency = parsePep508(quoted[1] ?? "", index + 1);
        if (dependency !== undefined) {
          dependencies.push(dependency);
        }
      }
      inDependencyArray = !body.includes("]");
      continue;
    }

    if (DEPENDENCY_TABLE_RE.test(section)) {
      const entry = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$/);
      const name = entry?.[1];
      if (name === undefined || name.toLowerCase() === "python") {
        continue;
      }
      const spec = tableEntryVersion(entry?.[2] ?? "") ?? "";
      dependencies.push({
        ecosystem: "PyPI",
        name: normalizePythonName(name),
        rawVersion: spec,
        version: exactFromTableSpec(spec),
        line: index + 1,
      });
    }
  }
  return dependencies;
}

/** Parses `go.mod` `require` directives (single-line and block form). Versions lose their `v` prefix and `+incompatible`. */
export function parseGoMod(content: string): ManifestDependency[] {
  const dependencies: ManifestDependency[] = [];
  let inRequireBlock = false;
  for (const [index, rawLine] of content.split("\n").entries()) {
    const line = rawLine.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && line === ")") {
      inRequireBlock = false;
      continue;
    }
    const requirement = inRequireBlock ? line : line.match(/^require\s+(.+)$/)?.[1];
    const parts = requirement?.split(/\s+/);
    const name = parts?.[0];
    const rawVersion = parts?.[1];
    if (name === undefined || rawVersion === undefined || name === "") {
      continue;
    }
    dependencies.push({
      ecosystem: "Go",
      name,
      rawVersion,
      version: rawVersion.replace(/^v/, "").replace(/\+incompatible$/, ""),
      line: index + 1,
    });
  }
  return dependencies;
}

/** Python/Go manifest parsers by basename. */
export function manifestParserFor(filePath: string): ((content: string) => ManifestDependency[]) | undefined {
  const basename = filePath.split("/").at(-1) ?? "";
  if (/^requirements[\w.-]*\.txt$/.test(basename)) {
    return parseRequirementsTxt;
  }
  if (basename === "pyproject.toml" || basename === "Pipfile") {
    return parsePyprojectOrPipfile;
  }
  if (basename === "go.mod") {
    return parseGoMod;
  }
  return undefined;
}
