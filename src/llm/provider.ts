/**
 * Provider abstraction — the LLM-01 pluggability seam.
 *
 * Every LLM-backed enrichment in this project goes through a single
 * `ProviderAdapter` contract so the rest of the codebase (the future
 * wiring plan, 07-03) never imports `@anthropic-ai/sdk` or `openai`
 * directly. This keeps the provider swap (Anthropic <-> OpenAI/Ollama
 * <-> Noop) a one-line factory decision instead of a call-site branch.
 *
 * `selectAdapter` is the ONLY place provider selection happens, and it is a
 * pure function of an injected env object (never `process.env` directly),
 * which is what makes it trivially unit-testable with a plain literal — see
 * src/llm/adapters/select.test.ts. The default, when no provider AND its
 * matching key are both present, is always `NoopAdapter` (T-07-06:
 * offline/no-LLM is the default and must never be silently upgraded to a
 * network-backed adapter).
 */
import { AnthropicAdapter, NoopAdapter, OpenAIAdapter } from "./adapters/index.js";

/**
 * The single contract every LLM provider wraps. Deliberately minimal —
 * one stateless async method — so adding a new provider never requires
 * touching call sites, only adding a class that implements this shape and
 * wiring it into `selectAdapter`.
 */
export interface ProviderAdapter {
  /** Stable provider identifier, used for logging/diagnostics and tests. */
  readonly name: "anthropic" | "openai" | "noop";
  /**
   * Given a single fully-built prompt string, returns the provider's text
   * response (or "" on any failure/degradation — see each adapter's own
   * try/catch). Never throws.
   */
  generate(prompt: string): Promise<string>;
}

/**
 * Pure factory: reads `env.IMMUNOGEN_PROVIDER` and the matching provider's
 * API key from the injected `env` object only (never `process.env`
 * directly — that is what lets tests pass a plain literal with no global
 * mutation/restoration needed).
 *
 * Selection rule (mirrors STACK.md's "LLM Fix-Prompt Layer" provider-
 * selection pattern):
 *   - `IMMUNOGEN_PROVIDER === "anthropic"` AND `ANTHROPIC_API_KEY` is a
 *     non-empty string -> AnthropicAdapter
 *   - `IMMUNOGEN_PROVIDER === "openai"` AND `OPENAI_API_KEY` is a
 *     non-empty string -> OpenAIAdapter (OPENAI_BASE_URL passed through,
 *     may be undefined)
 *   - anything else (provider absent, unknown provider, or the matching
 *     key missing) -> NoopAdapter
 */
export function selectAdapter(env: NodeJS.ProcessEnv): ProviderAdapter {
  if (env.IMMUNOGEN_PROVIDER === "anthropic" && isNonEmptyString(env.ANTHROPIC_API_KEY)) {
    return new AnthropicAdapter(env.ANTHROPIC_API_KEY);
  }

  if (env.IMMUNOGEN_PROVIDER === "openai" && isNonEmptyString(env.OPENAI_API_KEY)) {
    return new OpenAIAdapter(env.OPENAI_API_KEY, env.OPENAI_BASE_URL);
  }

  return new NoopAdapter();
}

/** True when `value` is a defined, non-empty string (a usable API key). */
function isNonEmptyString(value: string | undefined): value is string {
  return typeof value === "string" && value.length > 0;
}
