/**
 * Test-wide guard: package-registry lookups (DEP-02) never reach the real
 * npm / PyPI registries from the test suite. They get an inconclusive 418,
 * which the detector treats as "unknown" (no finding, no retry), so scans of
 * fixtures stay deterministic and offline. Tests that exercise DEP-02 spy on
 * `fetch` themselves, which takes precedence over this wrapper.
 */
const realFetch = globalThis.fetch;

globalThis.fetch = (input, init) => {
  const url = input instanceof Request ? input.url : input.toString();
  if (/^https:\/\/(?:registry\.npmjs\.org|pypi\.org)\//.test(url)) {
    return Promise.resolve(new Response(null, { status: 418 }));
  }
  return realFetch(input, init);
};
