/**
 * Skill-parity proof — asserts the Claude Code skill wrapper
 * (.claude/skills/immunogen/scan.mjs's `runScanSkill`) reports the SAME
 * Ship Score and finding count as the library `scan()` export on the same
 * target directory (DIST-03, T-08-13).
 *
 * This is a standalone node script, NOT a vitest test (mirrors
 * tests/dist/dual-import.test.mjs's convention): it imports the real BUILT
 * dist (`../../dist/index.js`) and the real skill wrapper
 * (`../../.claude/skills/immunogen/scan.mjs`) the way a Claude Code
 * runtime actually invokes them, so it proves the SHIPPED skill path has no
 * drift — not a vitest-transpiled view of src/. It is invoked directly via
 * `node tests/dist/skill-parity.test.mjs` after a build (`pnpm run build`),
 * and is never picked up by vitest.config.ts's include globs (those match
 * `*.test.ts`, not `*.test.mjs`).
 *
 * Why this test can't fail on absolute counts by design: scan() is
 * deterministic and offline by default (src/index.ts), and both the
 * library call and the wrapper call go through the exact same scan()
 * with no options — the wrapper never reads/forwards provider env vars.
 * Given that, same input MUST produce identical (score, count) UNLESS
 * something introduced drift: a stray env var only one caller sees, a
 * different working directory, or (worst case) the wrapper accidentally
 * enabling LLM enrichment. This test asserts PARITY — equality between the
 * two callers on the same dir — not any particular absolute number; it may
 * legitimately hit the OSV offline-fallback path (scanIncomplete), and that
 * is fine, because both sides would hit it identically and still match.
 */
import { scan } from "../../dist/index.js";
import { runScanSkill } from "../../.claude/skills/immunogen/scan.mjs";

const VULNERABLE_FIXTURE = "tests/fixtures/vulnerable-apps/nextjs-kitchen-sink";
const CLEAN_FIXTURE = "tests/fixtures/scan/clean";

/**
 * Runs both callers on the same directory and asserts (score, count)
 * parity. Throws a descriptive error identifying exactly which fixture and
 * which field diverged on any mismatch.
 */
async function assertParity(fixtureLabel, fixturePath) {
  const libraryResult = await scan(fixturePath);
  const wrapperResult = await runScanSkill(fixturePath);

  const libraryScore = libraryResult.score.score;
  const libraryCount = libraryResult.findings.length;

  if (wrapperResult.score !== libraryScore) {
    throw new Error(
      `Skill-parity FAILED on ${fixtureLabel} (${fixturePath}): score mismatch — ` +
        `wrapper=${wrapperResult.score} library=${libraryScore}`,
    );
  }

  if (wrapperResult.count !== libraryCount) {
    throw new Error(
      `Skill-parity FAILED on ${fixtureLabel} (${fixturePath}): finding count mismatch — ` +
        `wrapper=${wrapperResult.count} library=${libraryCount}`,
    );
  }

  console.log(
    `Skill-parity OK on ${fixtureLabel} (${fixturePath}): score=${libraryScore} count=${libraryCount}`,
  );
}

await assertParity("vulnerable fixture", VULNERABLE_FIXTURE);
await assertParity("clean fixture", CLEAN_FIXTURE);

console.log(
  "Skill-parity CONFIRMED: wrapper score+count == library scan() score.score+findings.length on all fixtures.",
);
