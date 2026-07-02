/**
 * ENG-05 self-test fixture — DO NOT IMPORT FROM PRODUCTION CODE.
 *
 * This file exists for exactly one reason: to prove the no-execute lint
 * ruleset (eslint.config.js) actually fires. It deliberately commits all
 * three forbidden patterns immunogen's static-only safety promise depends on:
 *
 *   1. importing `node:child_process` (no-restricted-imports +
 *      security/detect-child-process)
 *   2. calling `exec(...)` (no-restricted-syntax exec selector)
 *   3. calling `eval(...)` (no-restricted-syntax eval selector)
 *
 * It is excluded from the default `pnpm lint` run (eslint.config.js ignores
 * `src/__fixtures__/**`) so the clean scaffold stays green. Verify the rule
 * fires with a scoped, ignore-disabled invocation:
 *
 *   npx eslint --no-ignore src/__fixtures__/no-execute-sample.ts
 *
 * That command MUST exit non-zero. If it ever exits 0, the no-execute
 * ruleset has been silently weakened and ENG-05 is no longer enforced.
 */

// Violation 1: forbidden import (no-restricted-imports + detect-child-process)
import { exec } from "node:child_process";

// Violation 2: forbidden call (no-restricted-syntax exec selector)
exec("ls");

// Violation 3: forbidden call (no-restricted-syntax eval selector)
eval("1+1");
