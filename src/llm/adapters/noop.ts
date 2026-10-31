/**
 * NoopAdapter — the mandatory zero-setup default.
 *
 * `selectAdapter` returns this whenever no provider is configured, an
 * unrecognized provider name is set, or the matching API key is missing. It
 * imports no SDK and performs no network call; the enricher short-circuits on
 * it without calling `generate()` at all.
 */
import type { ProviderAdapter } from "../provider.js";

export class NoopAdapter implements ProviderAdapter {
  readonly name = "noop" as const;
  readonly model = "none";

  generate(prompt: string): Promise<string> {
    void prompt;
    return Promise.resolve("");
  }
}
