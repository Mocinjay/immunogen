/**
 * NoopAdapter — the mandatory zero-setup default (T-07-06).
 *
 * `selectAdapter` returns this whenever no provider is configured, an
 * unrecognized provider name is set, or the matching API key is missing.
 * It imports NO SDK and performs NO network call — `generate()` always
 * resolves to an empty string, meaning "no fix prompt" for the caller.
 * This is the adapter that makes the offline/no-LLM path the default: the
 * deterministic scan must be correct and useful with zero setup.
 */
import type { ProviderAdapter } from "../provider.js";

export class NoopAdapter implements ProviderAdapter {
  readonly name = "noop" as const;

  generate(prompt: string): Promise<string> {
    void prompt;
    return Promise.resolve("");
  }
}
