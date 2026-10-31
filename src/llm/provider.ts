/**
 * Provider abstraction — the LLM pluggability seam.
 *
 * Every LLM-backed enrichment goes through a single `ProviderAdapter`
 * contract so nothing outside `src/llm/adapters/` imports `@anthropic-ai/sdk`
 * or `openai` directly.
 *
 * `selectAdapter` is the ONLY place provider selection happens, and it is a
 * pure function of an injected env object (never `process.env` directly), so
 * it is unit-testable with a plain literal (src/llm/adapters/select.test.ts).
 * The default, when no provider AND its matching key are both present, is
 * always `NoopAdapter`: offline/no-LLM is the default and is never silently
 * upgraded to a network-backed adapter.
 */
import { AnthropicAdapter, NoopAdapter, OpenAIAdapter } from "./adapters/index.js";

import type { Diagnostic } from "../core/types.js";

/** The single contract every LLM provider wraps. */
export interface ProviderAdapter {
  /** Stable provider identifier, used for diagnostics and tests. */
  readonly name: "anthropic" | "openai" | "noop";
  /** The model id requests are sent to. */
  readonly model: string;
  /**
   * Given a single fully-built prompt string, returns the provider's text
   * response ("" when it declined). REJECTS on transport/API failure — the
   * enricher catches that per finding and reports it as a diagnostic.
   */
  generate(prompt: string): Promise<string>;
}

/** Providers `IMMUNOGEN_PROVIDER` accepts, with the env var holding each one's key. */
const PROVIDER_KEYS: ReadonlyMap<string, "ANTHROPIC_API_KEY" | "OPENAI_API_KEY"> = new Map([
  ["anthropic", "ANTHROPIC_API_KEY"],
  ["openai", "OPENAI_API_KEY"],
]);

/**
 * Pure factory over the injected `env`:
 *   - `IMMUNOGEN_PROVIDER=anthropic` + non-empty `ANTHROPIC_API_KEY` -> AnthropicAdapter
 *   - `IMMUNOGEN_PROVIDER=openai` + non-empty `OPENAI_API_KEY` -> OpenAIAdapter
 *     (`OPENAI_BASE_URL` passed through for OpenAI-compatible servers)
 *   - anything else -> NoopAdapter
 * `IMMUNOGEN_MODEL`, when non-empty, overrides the adapter's default model.
 */
export function selectAdapter(env: NodeJS.ProcessEnv): ProviderAdapter {
  const model = isNonEmptyString(env.IMMUNOGEN_MODEL) ? env.IMMUNOGEN_MODEL : undefined;

  if (env.IMMUNOGEN_PROVIDER === "anthropic" && isNonEmptyString(env.ANTHROPIC_API_KEY)) {
    return new AnthropicAdapter(env.ANTHROPIC_API_KEY, model);
  }

  if (env.IMMUNOGEN_PROVIDER === "openai" && isNonEmptyString(env.OPENAI_API_KEY)) {
    return new OpenAIAdapter(env.OPENAI_API_KEY, env.OPENAI_BASE_URL, model);
  }

  return new NoopAdapter();
}

/**
 * A warning when `IMMUNOGEN_PROVIDER` is set but cannot be honored (unknown
 * provider, or its API key is missing) — otherwise the user asked for LLM fix
 * prompts and silently got none. `undefined` when the configuration is
 * coherent (including "no provider requested").
 */
export function providerConfigDiagnostic(env: NodeJS.ProcessEnv): Diagnostic | undefined {
  const provider = env.IMMUNOGEN_PROVIDER;
  if (!isNonEmptyString(provider)) {
    return undefined;
  }
  const keyVar = PROVIDER_KEYS.get(provider);
  if (keyVar === undefined) {
    return {
      level: "warn",
      code: "LLM_CONFIG",
      message: `IMMUNOGEN_PROVIDER="${provider}" is not a supported provider (use "anthropic" or "openai"); LLM fix prompts are disabled.`,
    };
  }
  // eslint-disable-next-line security/detect-object-injection -- keyVar is one of two literal env var names from PROVIDER_KEYS
  if (!isNonEmptyString(env[keyVar])) {
    return {
      level: "warn",
      code: "LLM_CONFIG",
      message: `IMMUNOGEN_PROVIDER="${provider}" is set but ${keyVar} is empty; LLM fix prompts are disabled.`,
    };
  }
  return undefined;
}

/** True when `value` is a defined, non-empty string. */
function isNonEmptyString(value: string | undefined): value is string {
  return typeof value === "string" && value.length > 0;
}
