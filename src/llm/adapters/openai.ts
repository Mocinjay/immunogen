/**
 * OpenAIAdapter — wraps the `openai` SDK.
 *
 * Also the adapter for any OpenAI-compatible local inference server (Ollama,
 * vLLM, llama.cpp, LM Studio) via `OPENAI_BASE_URL` -> `baseURL`. Those
 * servers serve their own model names, so `IMMUNOGEN_MODEL` must name one of
 * them; the default only exists on OpenAI itself. When `baseURL` is undefined
 * the option is OMITTED from the client options (required by
 * `exactOptionalPropertyTypes`).
 *
 * `generate()` rejects on any SDK/network error; the enricher catches it and
 * records an `LLM_FAILED` diagnostic. Every call carries a bounded `timeout`.
 */
import OpenAI from "openai";

import type { ProviderAdapter } from "../provider.js";

/** Default model on api.openai.com. Override with `IMMUNOGEN_MODEL` (required for local servers). */
export const DEFAULT_OPENAI_MODEL = "gpt-4o-mini";

/** Token budget cap for a single fix-prompt generation call. */
const MAX_TOKENS = 1024;

/** Bounded wall-clock timeout (ms) for a single fix-prompt generation call. */
const REQUEST_TIMEOUT_MS = 30_000;

export class OpenAIAdapter implements ProviderAdapter {
  readonly name = "openai" as const;
  readonly model: string;
  private readonly client: OpenAI;

  constructor(apiKey: string, baseURL?: string, model: string = DEFAULT_OPENAI_MODEL) {
    this.client = new OpenAI({ apiKey, ...(baseURL !== undefined ? { baseURL } : {}) });
    this.model = model;
  }

  async generate(prompt: string): Promise<string> {
    const response = await this.client.chat.completions.create(
      {
        model: this.model,
        max_tokens: MAX_TOKENS,
        messages: [{ role: "user", content: prompt }],
      },
      { timeout: REQUEST_TIMEOUT_MS },
    );

    return response.choices[0]?.message.content ?? "";
  }
}
