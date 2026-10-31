# Contributing to immunogen

immunogen screens AI-built repos for launch-blocking contaminants. Contributions that add detection coverage, reduce false positives, or improve reporters are welcome.

## Dev setup

Requires Node.js 22+ and pnpm (`corepack enable` picks up the pinned version from `package.json`).

```sh
pnpm i
pnpm test
```

Other useful scripts: `pnpm run typecheck`, `pnpm run lint`, `pnpm run build`, and `pnpm run test:dist` (smoke-tests the built package and installed CLI; run after `build`). CI runs all of them on every push and pull request.

Tests never touch the network: OSV.dev and LLM providers are stubbed at their module boundary, so the suite passes offline.

## Adding a detector

Every detector implements `Detector { config: DetectorConfig; detect(ctx: DetectorContext): Promise<Finding[]> }` and registers in `src/detectors/registry.ts`'s `DEFAULT_DETECTORS`. Find the closest existing analog under `src/detectors/<category>/` (e.g. `src/detectors/secrets/entropy-detector.ts` for a text/regex detector, `src/detectors/auth/route-auth-detector.ts` for an AST-based one) and follow its shape — `ctx.ast` for AST detectors, `ctx.content` for text detectors, gated on `ctx.stackHints` if framework-specific.

**Every new detector must ship two fixtures**: a deliberately vulnerable/contaminated fixture that triggers the finding, and a clean fixture that proves zero false positives on legitimate code. Fixtures live under `tests/fixtures/`; skip `**/__tests__/`, `**/fixtures/`, `**/mocks/` when scanning.

## Non-negotiable rules

- **Never execute scanned code (ENG-05).** immunogen is static analysis only — no `import`/`require`/`eval` of anything under scan. This is enforced by the project's own lint rules and is a hard safety boundary, not a style preference.
- **False-positive discipline.** A noisy scanner that cries wolf is worse than none. Every finding needs a `confidence` level (HIGH/MEDIUM/LOW), and new detectors are expected to hold a low false-positive rate against the clean fixture set before merge.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, etc.), scoped where helpful (e.g. `feat(detectors): add X`).

## Releasing (maintainers)

1. Bump `version` in `package.json`, update the version-pinned install URLs in `README.md` (a test fails until they match), and move the `Unreleased` notes in `CHANGELOG.md` under the new version.
2. Merge to `main`. The `Release` workflow notices the unreleased version, re-runs the checks, packs the npm tarball, and creates the `v<version>` tag and GitHub Release with the tarball attached (`immunogen.tgz` always points at the latest release). Release notes come from the version's `CHANGELOG.md` section.
3. If an `NPM_TOKEN` repository secret is set, the workflow also publishes the same tarball to npm with provenance.

## Security issues

Report vulnerabilities in immunogen itself privately — see [SECURITY.md](./SECURITY.md).
