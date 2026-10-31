import { describe, expect, it } from "vitest";

import { DEFAULT_ANTHROPIC_MODEL } from "./anthropic.js";
import { DEFAULT_OPENAI_MODEL } from "./openai.js";
import { providerConfigDiagnostic, selectAdapter } from "../provider.js";

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

describe("selectAdapter — IMMUNOGEN_MODEL override", () => {
  it("defaults each adapter to its own model when IMMUNOGEN_MODEL is unset", () => {
    expect(selectAdapter({ IMMUNOGEN_PROVIDER: "anthropic", ANTHROPIC_API_KEY: "k" }).model).toBe(DEFAULT_ANTHROPIC_MODEL);
    expect(selectAdapter({ IMMUNOGEN_PROVIDER: "openai", OPENAI_API_KEY: "k" }).model).toBe(DEFAULT_OPENAI_MODEL);
  });

  it("routes requests to IMMUNOGEN_MODEL when set (required for Ollama-style servers)", () => {
    const adapter = selectAdapter({
      IMMUNOGEN_PROVIDER: "openai",
      OPENAI_API_KEY: "ollama",
      OPENAI_BASE_URL: "http://localhost:11434/v1",
      IMMUNOGEN_MODEL: "llama3.1",
    });

    expect(adapter.model).toBe("llama3.1");
  });
});

describe("providerConfigDiagnostic — misconfiguration is reported, not silent", () => {
  it("returns undefined when no provider is requested", () => {
    expect(providerConfigDiagnostic({})).toBeUndefined();
  });

  it("returns undefined for a coherent configuration", () => {
    expect(providerConfigDiagnostic({ IMMUNOGEN_PROVIDER: "anthropic", ANTHROPIC_API_KEY: "k" })).toBeUndefined();
  });

  it("warns when the provider's key is missing", () => {
    const diagnostic = providerConfigDiagnostic({ IMMUNOGEN_PROVIDER: "openai" });

    expect(diagnostic?.code).toBe("LLM_CONFIG");
    expect(diagnostic?.message).toContain("OPENAI_API_KEY");
  });

  it("warns on an unknown provider", () => {
    expect(providerConfigDiagnostic({ IMMUNOGEN_PROVIDER: "gemini", OPENAI_API_KEY: "k" })?.code).toBe("LLM_CONFIG");
  });
});
