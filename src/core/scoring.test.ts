import { describe, expect, it } from "vitest";

import { computeScore, gradeFor } from "./scoring.js";

import type { Finding, Severity } from "./types.js";

/**
 * Builds a complete `Finding` literal for the given `severity`. Every field
 * scoring.ts does NOT read is still populated so each literal compiles
 * under strict mode and resembles a real detector output.
 */
function makeFinding(severity: Severity, overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "SEC-01",
    category: "secrets",
    detectorName: "secretsDetector",
    file: "src/config.ts",
    line: 1,
    severity,
    confidence: "HIGH",
    message: `${severity} test finding`,
    remediation: "Remove the offending value.",
    ...overrides,
  };
}

describe("computeScore — empty findings", () => {
  it("returns a perfect score, Ready to ship band, and pass verdict", () => {
    expect(computeScore([])).toEqual({
      score: 100,
      band: "Ready to ship",
      verdict: "pass",
      criticalCount: 0,
      highCount: 0,
      grade: "A",
      gradeLabel: "Immune",
    });
  });
});

describe("computeScore — severity weights", () => {
  it("one MEDIUM (weight 10) gives score 90", () => {
    const result = computeScore([makeFinding("MEDIUM")]);
    expect(result.score).toBe(90);
    expect(result.band).toBe("Ready to ship");
    expect(result.verdict).toBe("pass");
  });

  it("one HIGH (weight 25) gives score 75 and band Low risk", () => {
    const result = computeScore([makeFinding("HIGH")]);
    expect(result.score).toBe(75);
    expect(result.band).toBe("Low risk");
    expect(result.verdict).toBe("pass");
    expect(result.highCount).toBe(1);
  });

  it("two HIGH (weight 50) gives score 50 and band Moderate risk", () => {
    const result = computeScore([makeFinding("HIGH"), makeFinding("HIGH")]);
    expect(result.score).toBe(50);
    expect(result.band).toBe("Moderate risk");
    expect(result.verdict).toBe("pass");
    expect(result.highCount).toBe(2);
  });

  it("one LOW (weight 5) gives score 95", () => {
    const result = computeScore([makeFinding("LOW")]);
    expect(result.score).toBe(95);
    expect(result.band).toBe("Ready to ship");
  });

  it("INFO findings contribute zero weight", () => {
    const result = computeScore([makeFinding("INFO"), makeFinding("INFO")]);
    expect(result.score).toBe(100);
    expect(result.band).toBe("Ready to ship");
  });
});

describe("computeScore — critical hard cap (criterion 3, threat T-04-06)", () => {
  it("a single CRITICAL yields score <= 25 and verdict blocked", () => {
    const result = computeScore([makeFinding("CRITICAL")]);
    expect(result.score).toBeLessThanOrEqual(25);
    expect(result.verdict).toBe("blocked");
    expect(result.criticalCount).toBe(1);
  });

  it("a lone CRITICAL produces exactly score 20 (100 - max(50, 80))", () => {
    const result = computeScore([makeFinding("CRITICAL")]);
    expect(result.score).toBe(20);
    expect(result.band).toBe("High risk");
    expect(result.verdict).toBe("blocked");
  });

  it("CRITICAL forces blocked even alongside otherwise-light findings", () => {
    const result = computeScore([makeFinding("CRITICAL"), makeFinding("LOW")]);
    expect(result.score).toBeLessThanOrEqual(25);
    expect(result.verdict).toBe("blocked");
  });

  it("many CRITICAL findings still floor at <= 25, never escape the cap upward", () => {
    const result = computeScore([
      makeFinding("CRITICAL"),
      makeFinding("CRITICAL"),
      makeFinding("CRITICAL"),
    ]);
    expect(result.score).toBeLessThanOrEqual(25);
    expect(result.verdict).toBe("blocked");
    expect(result.criticalCount).toBe(3);
  });
});

describe("computeScore — verdict without CRITICAL findings", () => {
  it("blocks on score alone when it falls into the High risk band (score < 40)", () => {
    const result = computeScore([
      makeFinding("HIGH"),
      makeFinding("HIGH"),
      makeFinding("HIGH"),
    ]);
    expect(result.criticalCount).toBe(0);
    expect(result.score).toBeLessThan(40);
    expect(result.band).toBe("High risk");
    expect(result.verdict).toBe("blocked");
  });

  it("passes at the Moderate risk floor (score === 40)", () => {
    const result = computeScore([
      makeFinding("HIGH"),
      makeFinding("HIGH"),
      makeFinding("MEDIUM"),
    ]);
    expect(result.score).toBe(40);
    expect(result.band).toBe("Moderate risk");
    expect(result.verdict).toBe("pass");
  });
});

describe("computeScore — band thresholds", () => {
  // Every non-CRITICAL severity weight (HIGH 25, MEDIUM 10, LOW 5) is a
  // multiple of 5, so only risk values that are themselves multiples of 5
  // are exactly reachable without a CRITICAL finding. Boundary scores below
  // are chosen accordingly — each pair straddles a real band edge from
  // computeScore's bandFor() thresholds (90 / 70 / 40).
  it.each<[number, ReturnType<typeof computeScore>["band"]]>([
    [100, "Ready to ship"],
    [90, "Ready to ship"],
    [85, "Low risk"],
    [70, "Low risk"],
    [65, "Moderate risk"],
    [40, "Moderate risk"],
    [35, "High risk"],
    [0, "High risk"],
  ])("score %i maps to band %s", (targetScore, expectedBand) => {
    // rawPoints = 100 - targetScore, built purely from LOW (weight 5)
    // findings — every target risk value below is a multiple of 5, so a
    // count of LOW findings reaches it exactly with no CRITICAL/HIGH
    // skewing the verdict floor under test.
    const risk = 100 - targetScore;
    const lowCount = risk / 5;
    const findings: Finding[] = Array.from({ length: lowCount }, () => makeFinding("LOW"));

    const result = computeScore(findings);
    expect(result.score).toBe(targetScore);
    expect(result.band).toBe(expectedBand);
  });
});

describe("computeScore — counts", () => {
  it("criticalCount and highCount reflect the input regardless of other severities", () => {
    const result = computeScore([
      makeFinding("CRITICAL"),
      makeFinding("CRITICAL"),
      makeFinding("HIGH"),
      makeFinding("MEDIUM"),
      makeFinding("LOW"),
      makeFinding("INFO"),
    ]);
    expect(result.criticalCount).toBe(2);
    expect(result.highCount).toBe(1);
  });
});

describe("computeScore — determinism (threat T-04-05)", () => {
  it("the same findings in a different order produce a deep-equal ShipScore", () => {
    const findings: Finding[] = [
      makeFinding("CRITICAL", { file: "a.ts" }),
      makeFinding("HIGH", { file: "b.ts" }),
      makeFinding("MEDIUM", { file: "c.ts" }),
      makeFinding("LOW", { file: "d.ts" }),
      makeFinding("INFO", { file: "e.ts" }),
    ];
    const shuffled = [findings[4], findings[1], findings[3], findings[0], findings[2]] as Finding[];

    const original = computeScore(findings);
    const reordered = computeScore(shuffled);

    expect(reordered).toEqual(original);
  });

  it("calling computeScore twice with the same input yields identical results", () => {
    const findings: Finding[] = [makeFinding("HIGH"), makeFinding("MEDIUM")];

    const first = computeScore(findings);
    const second = computeScore(findings);

    expect(second).toEqual(first);
  });
});

describe("gradeFor — auto-F on any CRITICAL", () => {
  it("returns F when hasCritical is true regardless of how high the score is", () => {
    expect(gradeFor(100, true)).toBe("F");
    expect(gradeFor(90, true)).toBe("F");
    expect(gradeFor(0, true)).toBe("F");
  });
});

describe("gradeFor — boundary thresholds (no CRITICAL)", () => {
  it.each<[number, ReturnType<typeof gradeFor>]>([
    [90, "A"],
    [89, "B"],
    [75, "B"],
    [74, "C"],
    [55, "C"],
    [54, "D"],
    [35, "D"],
    [34, "F"],
    [100, "A"],
    [0, "F"],
  ])("gradeFor(%i, false) === %s", (score, expectedGrade) => {
    expect(gradeFor(score, false)).toBe(expectedGrade);
  });
});

describe("computeScore — grade + gradeLabel wiring", () => {
  it("a lone CRITICAL yields grade F even though it is the only finding (auto-fail overrides score)", () => {
    const result = computeScore([makeFinding("CRITICAL")]);
    expect(result.criticalCount).toBe(1);
    expect(result.grade).toBe("F");
    expect(result.gradeLabel).toBe("Critical");
  });

  it("an empty scan (score 100) yields grade A / label Immune", () => {
    const result = computeScore([]);
    expect(result.grade).toBe("A");
    expect(result.gradeLabel).toBe("Immune");
  });

  it("pairs every grade with its exact status label", () => {
    const cases: Array<{ findings: Finding[]; grade: string; label: string }> = [
      { findings: [], grade: "A", label: "Immune" },
      { findings: [makeFinding("HIGH")], grade: "B", label: "Healthy" }, // rawPoints 25, score 75
      {
        findings: [makeFinding("HIGH"), makeFinding("LOW")],
        grade: "C",
        label: "Symptomatic",
      }, // rawPoints 30, score 70
      {
        findings: [makeFinding("HIGH"), makeFinding("HIGH"), makeFinding("MEDIUM")],
        grade: "D",
        label: "Infected",
      }, // rawPoints 60, score 40
      { findings: [makeFinding("CRITICAL")], grade: "F", label: "Critical" }, // auto-fail
    ];

    for (const { findings, grade, label } of cases) {
      const result = computeScore(findings);
      expect(result.grade).toBe(grade);
      expect(result.gradeLabel).toBe(label);
    }
  });

  it("grade stays order-independent alongside score/band/verdict (threat T-04-05)", () => {
    const findings: Finding[] = [
      makeFinding("CRITICAL", { file: "a.ts" }),
      makeFinding("HIGH", { file: "b.ts" }),
      makeFinding("MEDIUM", { file: "c.ts" }),
    ];
    const shuffled = [findings[2], findings[0], findings[1]] as Finding[];

    expect(computeScore(shuffled)).toEqual(computeScore(findings));
  });
});
