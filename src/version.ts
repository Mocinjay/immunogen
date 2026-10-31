/**
 * The package version — the single source for the CLI `--version`, the
 * live-URL User-Agent, and SARIF `tool.driver.version`.
 *
 * Injected at build time by tsup and at test time by vitest (`define` in
 * tsup.config.ts / vitest.config.ts, both read from package.json), so the
 * bundled library never has to locate package.json at runtime — which the
 * CJS build cannot do via `import.meta.url`. Running the TypeScript source
 * any other way (e.g. `tsx`) falls back to a dev marker.
 */
declare const __IMMUNOGEN_VERSION__: string | undefined;

export const VERSION: string = typeof __IMMUNOGEN_VERSION__ === "string" ? __IMMUNOGEN_VERSION__ : "0.0.0-dev";

/** User-Agent sent on every live-URL request — identifies the tool and links to its source. */
export const USER_AGENT = `immunogen/${VERSION} (+https://github.com/Mocinjay/immunogen)`;
