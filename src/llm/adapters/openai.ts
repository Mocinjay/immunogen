/**
 * OpenAIAdapter — wraps the `openai` SDK (6.44.0, exact-pinned).
 *
 * Also the universal adapter for any OpenAI-compatible local inference
 * server (Ollama, vLLM, llama.cpp, LM Studio) via `OPENAI_BASE_URL` ->
 * `baseURL`. When `baseURL` is undefined the option is OMITTED entirely
 * from the client-options object (not passed as `baseURL: undefined`) —
 * required by this project's `exactOptionalPropertyTypes: true` tsconfig
 * setting, which treats an explicit `undefined` value as distinct from an
 * absent key for optional properties.
 *
 * Every test for this class stubs the SDK via `vi.mock("openai", ...)`
 * (see openai.test.ts) and asserts the constructor receives `baseURL`
 * exactly when one was passed in, and omits it otherwise — proving
 * OPENAI_BASE_URL routing reaches the SDK (criterion 5) without any real
 * network call.
 */
import OpenAI from "openai";

import type { ProviderAdapter } from "../provider.js";

/** Small, fixed model id — a fix-prompt is a short, bounded generation, not a long-form task. */
const MODEL = "gpt-4o-mini";

/** Token budget cap for a single fix-prompt generation call. */
const MAX_TOKENS = 1024;

/** Bounded wall-clock timeout (ms) for a single fix-prompt generation call — a hung provider must degrade, never stall the scan (T-07-04). */
const REQUEST_TIMEOUT_MS = 30_000;

export class OpenAIAdapter implements ProviderAdapter {
  readonly name = "openai" as const;
  private readonly client: OpenAI;

  constructor(apiKey: string, baseURL?: string) {
    this.client = new OpenAI({ apiKey, ...(baseURL !== undefined ? { baseURL } : {}) });
  }

  async generate(prompt: string): Promise<string> {
    try {
      const response = await this.client.chat.completions.create(
        {
          model: MODEL,
          max_tokens: MAX_TOKENS,
          messages: [{ role: "user", content: prompt }],
        },
        { timeout: REQUEST_TIMEOUT_MS },
      );

      return response.choices[0]?.message.content ?? "";
    } catch {
      // Any SDK/network failure degrades to "no fix prompt", never a
      // crashed scan (T-07-04).
      return "";
    }
  }
}
