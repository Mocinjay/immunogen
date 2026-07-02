/**
 * FIXTURE FILE — used by src/scan.test.ts to prove the end-to-end clean-scan
 * path (criterion 5: a repo with no leaked credentials yields a high score
 * and a non-blocked verdict). Deliberately ordinary code: a short,
 * low-entropy label and nothing that would anchor the entropy detector.
 */
export function greet(name: string): string {
  const label = "hello";
  return `${label}, ${name}!`;
}

export const appName = "fixture-app";
