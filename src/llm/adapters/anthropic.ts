/**
 * AnthropicAdapter — wraps `@anthropic-ai/sdk` (0.104.2, exact-pinned).
 *
 * Every test for this class stubs the SDK via `vi.mock("@anthropic-ai/sdk",
 * ...)` (see anthropic.test.ts) — this file is never exercised against the
 * real network or a real API key in the test suite.
 *
 * `generate()` wraps the whole SDK call in try/catch, degrading to `""` on
 * ANY error (T-07-04: a provider hang/error must never abort the
 * deterministic scan, only degrade to "no fix prompt"). `max_tokens` is a
 * small fixed bound to cap per-call cost. Every call also carries a bounded
 * `timeout` (REQUEST_TIMEOUT_MS) so a hung/unresponsive provider degrades
 * to `""` within a fixed wall-clock bound instead of stalling the scan
 * indefinitely.
 */
import Anthropic from "@anthropic-ai/sdk";

import type { ProviderAdapter } from "../provider.js";

/** Small, fixed model id — a fix-prompt is a short, bounded generation, not a long-form task. */
const MODEL = "claude-3-5-haiku-latest";

/** Token budget cap for a single fix-prompt generation call. */
const MAX_TOKENS = 1024;

/** Bounded wall-clock timeout (ms) for a single fix-prompt generation call — a hung provider must degrade, never stall the scan (T-07-04). */
const REQUEST_TIMEOUT_MS = 30_000;

export class AnthropicAdapter implements ProviderAdapter {
  readonly name = "anthropic" as const;
  private readonly client: Anthropic;

  constructor(apiKey: string) {
    this.client = new Anthropic({ apiKey });
  }

  async generate(prompt: string): Promise<string> {
    try {
      const response = await this.client.messages.create(
        {
          model: MODEL,
          max_tokens: MAX_TOKENS,
          messages: [{ role: "user", content: prompt }],
        },
        { timeout: REQUEST_TIMEOUT_MS },
      );

      return response.content
        .filter((block): block is Anthropic.TextBlock => block.type === "text")
        .map((block) => block.text)
        .join("");
    } catch {
      // Any SDK/network failure degrades to "no fix prompt", never a
      // crashed scan (T-07-04).
      return "";
    }
  }
}
