import { describe, expect, it } from "vitest";

import { selectAdapter } from "../provider.js";

/**
 * selectAdapter is a pure function of an injected env object — these tests
 * use ONLY plain literals, never `process.env`, and import no SDK. This
 * proves the offline-default contract (T-07-06) entirely at the factory
 * level: Noop unless a provider AND its matching key are both present.
 */
describe("selectAdapter — offline-default factory (LLM-01)", () => {
  it("returns NoopAdapter when env is empty", () => {
    const adapter = selectAdapter({});

    expect(adapter.name).toBe("noop");
  });

  it("returns NoopAdapter when IMMUNOGEN_PROVIDER is 'anthropic' but ANTHROPIC_API_KEY is missing", () => {
    const adapter = selectAdapter({ IMMUNOGEN_PROVIDER: "anthropic" });

    expect(adapter.name).toBe("noop");
  });

  it("returns NoopAdapter when IMMUNOGEN_PROVIDER is 'anthropic' but ANTHROPIC_API_KEY is an empty string", () => {
    const adapter = selectAdapter({ IMMUNOGEN_PROVIDER: "anthropic", ANTHROPIC_API_KEY: "" });

    expect(adapter.name).toBe("noop");
  });

  it("returns AnthropicAdapter when IMMUNOGEN_PROVIDER is 'anthropic' and ANTHROPIC_API_KEY is set", () => {
    const adapter = selectAdapter({ IMMUNOGEN_PROVIDER: "anthropic", ANTHROPIC_API_KEY: "sk-ant-test" });

    expect(adapter.name).toBe("anthropic");
  });

  it("returns NoopAdapter when IMMUNOGEN_PROVIDER is 'openai' but OPENAI_API_KEY is missing", () => {
    const adapter = selectAdapter({ IMMUNOGEN_PROVIDER: "openai" });

    expect(adapter.name).toBe("noop");
  });

  it("returns OpenAIAdapter when IMMUNOGEN_PROVIDER is 'openai' and OPENAI_API_KEY is set", () => {
    const adapter = selectAdapter({ IMMUNOGEN_PROVIDER: "openai", OPENAI_API_KEY: "x" });

    expect(adapter.name).toBe("openai");
  });

  it("returns OpenAIAdapter when OPENAI_BASE_URL is also set (Ollama-style local routing)", () => {
    const adapter = selectAdapter({
      IMMUNOGEN_PROVIDER: "openai",
      OPENAI_API_KEY: "ollama",
      OPENAI_BASE_URL: "http://localhost:11434/v1",
    });

    expect(adapter.name).toBe("openai");
  });

  it("returns NoopAdapter for an unrecognized IMMUNOGEN_PROVIDER value, even with keys present", () => {
    const adapter = selectAdapter({
      IMMUNOGEN_PROVIDER: "not-a-real-provider",
      ANTHROPIC_API_KEY: "sk-ant-test",
      OPENAI_API_KEY: "x",
    });

    expect(adapter.name).toBe("noop");
  });
});
