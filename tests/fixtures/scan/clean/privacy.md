<!--
  FIXTURE FILE — satisfies legalDetector's (src/detectors/legal/legal-detector.ts,
  LEGAL-01) privacy/terms path-vocabulary check so this fixture is genuinely
  zero-findings across every detector, not just secrets. Discovered as a gap
  during the golden-suite build (tests/golden/golden.test.ts, plan 08-01):
  this fixture previously had no privacy/terms evidence and so legitimately
  fired LEGAL-01 on every scan, contradicting its own "clean" name and this
  repo's golden-fixture contract that clean fixtures are zero findings.
-->

# Privacy Policy

This is a minimal fixture app with no real user data collection.
