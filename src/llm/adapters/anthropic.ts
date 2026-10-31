/**
 * AnthropicAdapter — wraps `@anthropic-ai/sdk` for fix-prompt generation.
 *
 * Every test for this class stubs the SDK via `vi.mock("@anthropic-ai/sdk",
 * ...)` (see anthropic.test.ts) — this file is never exercised against the
 * real network or a real API key in the test suite.
 *
 * `generate()` rejects on any SDK/network error; the enricher catches it,
 * leaves that finding un-enriched, and records an `LLM_FAILED` diagnostic so
 * a broken key or model is visible instead of silently producing nothing.
 * Every call carries a bounded `timeout` (REQUEST_TIMEOUT_MS) so a hung
 * provider degrades within a fixed wall-clock bound.
 */
import Anthropic from "@anthropic-ai/sdk";

import type { ProviderAdapter } from "../provider.js";

/**
 * Default model: a fix prompt is a short, bounded generation, so the current
 * Haiku tier keeps the per-finding cost negligible. Override with
 * `IMMUNOGEN_MODEL`.
 */
export const DEFAULT_ANTHROPIC_MODEL = "claude-haiku-5-5";

/** Output budget for one fix prompt. Thinking tokens count toward it, so it is not set tight. */
const MAX_TOKENS = 4096;

/** Bounded wall-clock timeout (ms) for a single fix-prompt generation call. */
const REQUEST_TIMEOUT_MS = 30_000;

export class AnthropicAdapter implements ProviderAdapter {
  readonly name = "anthropic" as const;
  readonly model: string;
  private readonly client: Anthropic;

  constructor(apiKey: string, model: string = DEFAULT_ANTHROPIC_MODEL) {
    this.client = new Anthropic({ apiKey });
    this.model = model;
  }

  async generate(prompt: string): Promise<string> {
    const response = await this.client.messages.create(
      {
        model: this.model,
        max_tokens: MAX_TOKENS,
        // A short, mechanical rewrite: low effort keeps latency and spend down.
        output_config: { effort: "low" },
        messages: [{ role: "user", content: prompt }],
      },
      { timeout: REQUEST_TIMEOUT_MS },
    );

    if (response.stop_reason === "refusal") {
      return "";
    }
    return response.content
      .filter((block): block is Anthropic.TextBlock => block.type === "text")
      .map((block) => block.text)
      .join("");
  }
}
