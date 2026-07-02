// @ts-check
/**
 * immunogen ESLint flat config (ESLint 9).
 *
 * Enforces ENG-05: immunogen's own scanner source never executes scanned code.
 * Three complementary mechanisms cover src/** and bin/**:
 *   1. eslint-plugin-security's `detect-child-process` (static AST heuristic
 *      flagging dynamic-looking child_process calls).
 *   2. `no-restricted-imports` forbidding `child_process` / `node:child_process`
 *      imports outright (catches the import even if it is never called).
 *   3. `no-restricted-syntax` AST selectors forbidding bare `eval(...)` and
 *      member calls to exec/execSync/spawn/spawnSync/fork regardless of which
 *      module they came from (catches re-exports/aliases of the primitive).
 *
 * NOTE: written as eslint.config.js (not .ts) — ESLint 9's TypeScript config
 * loader requires the `jiti` package, which is not declared in package.json's
 * devDependencies (Plan 01 owns package.json; this plan must not edit it).
 * Flat config has identical semantics in .js; `// @ts-check` + JSDoc keeps
 * editor type-checking without adding a dependency.
 *
 * src/__fixtures__/no-execute-sample.ts deliberately VIOLATES this ruleset
 * (it exists to prove the rule fires — see that file's own header comment).
 * It is excluded here from the default `pnpm lint` run via `ignores` below;
 * verify enforcement with a scoped, `--no-ignore` eslint invocation on it.
 *
 * src/**\/*.test-d.ts files are compile-time-only type-test files (see
 * src/core/types.test-d.ts) — they intentionally contain `@ts-expect-error`
 * directives and unused `satisfies`-typed bindings that the type-checked
 * rule set would otherwise flag. They are excluded here using the same
 * scoped-ignore mechanism as src/__fixtures__/** above; the type CHECK
 * itself is never disabled — `*.test-d.ts` stays inside tsconfig's
 * `include` and is fully checked by `pnpm typecheck`.
 */
import tsEslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import security from "eslint-plugin-security";

const ENG_05_MESSAGE =
  "immunogen is static-only — child_process/exec/spawn/eval is forbidden in scanner source (ENG-05)";

export default [
  // Never lint build output or dependencies.
  {
    ignores: ["dist/**", "node_modules/**"],
  },

  // typescript-eslint recommended (type-checked) base, wired to this
  // project's tsconfig so type-aware rules can resolve real types.
  // Scoped to src/** and bin/** — matching tsconfig.json's own `include` —
  // so root-level tooling configs (this file, tsup/vitest config) are never
  // sent through type-aware parsing (they are not part of the tsconfig
  // project and projectService cannot resolve types for them).
  ...tsEslint.configs["flat/recommended-type-checked"].map((config) => ({
    ...config,
    files: ["src/**/*.ts", "bin/**/*.ts"],
  })),
  {
    files: ["src/**/*.ts", "bin/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // eslint-plugin-security recommended baseline (registers the plugin +
  // its "warn"-level defaults across the whole project).
  security.configs.recommended,

  // ENG-05 no-execute ruleset — scoped to the scanner's own source.
  {
    files: ["src/**/*.ts", "bin/**/*.ts"],
    rules: {
      // Mechanism 1: heuristic detection of child_process usage.
      "security/detect-child-process": "error",

      // Mechanism 2: forbid importing the primitive at all.
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "child_process",
              message: ENG_05_MESSAGE,
            },
            {
              name: "node:child_process",
              message: ENG_05_MESSAGE,
            },
          ],
        },
      ],

      // Mechanism 3: forbid the execution primitives by AST shape, so an
      // aliased import or re-export still trips the rule.
      "no-restricted-syntax": [
        "error",
        {
          selector: "CallExpression[callee.name='eval']",
          message: ENG_05_MESSAGE,
        },
        {
          selector:
            "CallExpression[callee.property.name=/^(exec|execSync|spawn|spawnSync|fork)$/]",
          message: ENG_05_MESSAGE,
        },
        {
          selector:
            "CallExpression[callee.name=/^(exec|execSync|spawn|spawnSync|fork)$/]",
          message: ENG_05_MESSAGE,
        },
      ],
    },
  },

  // The no-execute fixture deliberately violates the ruleset above to prove
  // it fires (see Task 2 / src/__fixtures__/no-execute-sample.ts). Excluded
  // from the default `pnpm lint` run; verify it with:
  //   npx eslint --no-ignore src/__fixtures__/no-execute-sample.ts
  {
    ignores: ["src/__fixtures__/**"],
  },

  // Compile-time-only type-test files (*.test-d.ts) intentionally contain
  // `@ts-expect-error` directives and unused `satisfies`-typed bindings —
  // exempt them from lint the same way the fixture above is exempted. The
  // type CHECK is unaffected: these files remain inside tsconfig's
  // `include` and are fully checked by `pnpm typecheck`.
  {
    ignores: ["src/**/*.test-d.ts"],
  },
];
