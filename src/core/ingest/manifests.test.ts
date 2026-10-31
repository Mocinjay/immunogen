import { describe, expect, it } from "vitest";

import { manifestParserFor, parseGoMod, parsePyprojectOrPipfile, parseRequirementsTxt } from "./manifests.js";

const summarize = (deps: ReturnType<typeof parseGoMod>): string[] =>
  deps.map((dep) => `${dep.ecosystem}:${dep.name}@${dep.version ?? "-"} L${String(dep.line)}`);

describe("parseRequirementsTxt", () => {
  it("reads pinned and ranged requirements, normalizing names and skipping options/comments/URLs", () => {
    const content = [
      "# comment",
      "Flask==2.0.1",
      "requests[security]>=2.0  # trailing comment",
      "SQLAlchemy===1.4.0 ; python_version < '3.12'",
      "-r base.txt",
      "-e git+https://github.com/x/y#egg=y",
      "Django_REST_framework == 3.14.0",
    ].join("\n");

    expect(summarize(parseRequirementsTxt(content))).toEqual([
      "PyPI:flask@2.0.1 L2",
      "PyPI:requests@- L3",
      "PyPI:sqlalchemy@1.4.0 L4",
      "PyPI:django-rest-framework@3.14.0 L7",
    ]);
  });
});

describe("parsePyprojectOrPipfile", () => {
  it("reads PEP 621 dependencies (single- and multi-line) and optional groups", () => {
    const content = [
      "[project]",
      'name = "app"',
      'dependencies = ["fastapi==0.110.0", "pydantic>=2"]',
      "[project.optional-dependencies]",
      "dev = [",
      '  "pytest==8.0.0",',
      "]",
    ].join("\n");

    expect(summarize(parsePyprojectOrPipfile(content))).toEqual([
      "PyPI:fastapi@0.110.0 L3",
      "PyPI:pydantic@- L3",
      "PyPI:pytest@8.0.0 L6",
    ]);
  });

  it("reads Poetry tables, skipping python and treating a bare version as exact", () => {
    const content = [
      "[tool.poetry.dependencies]",
      'python = "^3.11"',
      'flask = "2.0.1"',
      'requests = "^2.31"',
      'supabase = { version = "2.3.0", optional = true }',
      "[tool.poetry.group.dev.dependencies]",
      'pytest = "8.0.0"',
    ].join("\n");

    expect(summarize(parsePyprojectOrPipfile(content))).toEqual([
      "PyPI:flask@2.0.1 L3",
      "PyPI:requests@- L4",
      "PyPI:supabase@2.3.0 L5",
      "PyPI:pytest@8.0.0 L7",
    ]);
  });

  it("reads Pipfile packages", () => {
    const content = ["[packages]", 'flask = "==2.0.1"', 'requests = "*"', "[dev-packages]", 'black = "==24.1.0"'].join("\n");

    expect(summarize(parsePyprojectOrPipfile(content))).toEqual([
      "PyPI:flask@2.0.1 L2",
      "PyPI:requests@- L3",
      "PyPI:black@24.1.0 L5",
    ]);
  });
});

describe("parseGoMod", () => {
  it("reads single-line and block requires, dropping v prefixes, +incompatible, and comments", () => {
    const content = [
      "module example.com/app",
      "go 1.22",
      "require github.com/gin-gonic/gin v1.9.0",
      "require (",
      "\tgithub.com/golang-jwt/jwt/v5 v5.2.0",
      "\tgithub.com/docker/docker v20.10.0+incompatible // indirect",
      ")",
    ].join("\n");

    expect(summarize(parseGoMod(content))).toEqual([
      "Go:github.com/gin-gonic/gin@1.9.0 L3",
      "Go:github.com/golang-jwt/jwt/v5@5.2.0 L5",
      "Go:github.com/docker/docker@20.10.0 L6",
    ]);
  });
});

describe("manifestParserFor", () => {
  it("selects a parser by basename", () => {
    expect(manifestParserFor("requirements.txt")).toBe(parseRequirementsTxt);
    expect(manifestParserFor("api/requirements-dev.txt")).toBe(parseRequirementsTxt);
    expect(manifestParserFor("pyproject.toml")).toBe(parsePyprojectOrPipfile);
    expect(manifestParserFor("Pipfile")).toBe(parsePyprojectOrPipfile);
    expect(manifestParserFor("svc/go.mod")).toBe(parseGoMod);
    expect(manifestParserFor("package.json")).toBeUndefined();
  });
});
