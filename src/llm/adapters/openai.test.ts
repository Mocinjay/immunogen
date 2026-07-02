import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Minimal shape of the arguments OpenAIAdapter.generate() passes to
 * `chat.completions.create` — typed explicitly (rather than importing the
 * real SDK's ChatCompletionCreateParams) so this fully-stubbed suite stays
 * decoupled from the real SDK's type surface while avoiding an unsafe
 * `any` on `mock.calls[0]?.[0]` member access.
 */
interface FakeChatCompletionsCreateArgs {
  max_tokens: number;
  messages: Array<{ role: string; content: string }>;
}

/** Minimal shape of the options passed to the OpenAI client constructor. */
interface FakeOpenAIClientOptions {
  apiKey: string;
  baseURL?: string;
}

// The openai SDK client is stubbed at the module boundary so this suite
// NEVER performs a real network call or requires a real API key (per the
// project's offline-deterministic test mandate). The fake constructor
// records the options it was called with so tests can assert the
// baseURL-threading contract (criterion 5) at the adapter level.
const chatCompletionsCreateMock =
  vi.fn<
    (args: FakeChatCompletionsCreateArgs, options?: { timeout?: number }) => Promise<unknown>
  >();
const openaiConstructorMock = vi.fn<(options: FakeOpenAIClientOptions) => void>();

vi.mock("openai", () => ({
  default: class FakeOpenAI {
    chat = { completions: { create: chatCompletionsCreateMock } };
    constructor(options: FakeOpenAIClientOptions) {
      openaiConstructorMock(options);
    }
  },
}));

const { OpenAIAdapter } = await import("./openai.js");

afterEach(() => {
  chatCompletionsCreateMock.mockReset();
  openaiConstructorMock.mockReset();
});

describe("OpenAIAdapter", () => {
  it("declares name === 'openai'", () => {
    const adapter = new OpenAIAdapter("x");

    expect(adapter.name).toBe("openai");
  });

  it("passes apiKey through with NO baseURL key when baseURL is omitted", () => {
    void new OpenAIAdapter("sk-openai-test");

    expect(openaiConstructorMock).toHaveBeenCalledWith({ apiKey: "sk-openai-test" });
    const calledWith = openaiConstructorMock.mock.calls[0]?.[0];
    expect(Object.prototype.hasOwnProperty.call(calledWith ?? {}, "baseURL")).toBe(false);
  });

  it("threads the injected baseURL through to the OpenAI client constructor (Ollama routing proof, criterion 5)", () => {
    void new OpenAIAdapter("ollama", "http://localhost:11434/v1");

    expect(openaiConstructorMock).toHaveBeenCalledWith({
      apiKey: "ollama",
      baseURL: "http://localhost:11434/v1",
    });
  });

  it("generate() returns choices[0].message.content", async () => {
    chatCompletionsCreateMock.mockResolvedValue({
      choices: [{ message: { content: "Add input validation on the endpoint." } }],
    });
    const adapter = new OpenAIAdapter("x");

    const result = await adapter.generate("How do I fix this finding?");

    expect(result).toBe("Add input validation on the endpoint.");
    expect(chatCompletionsCreateMock).toHaveBeenCalledTimes(1);
  });

  it("generate() returns '' when message.content is null", async () => {
    chatCompletionsCreateMock.mockResolvedValue({
      choices: [{ message: { content: null } }],
    });
    const adapter = new OpenAIAdapter("x");

    const result = await adapter.generate("prompt");

    expect(result).toBe("");
  });

  it("generate() calls chat.completions.create with the prompt as a single user message and a bounded max_tokens", async () => {
    chatCompletionsCreateMock.mockResolvedValue({ choices: [{ message: { content: "ok" } }] });
    const adapter = new OpenAIAdapter("x");

    await adapter.generate("the prompt text");

    const callArgs = chatCompletionsCreateMock.mock.calls[0]?.[0];
    expect(callArgs).toMatchObject({
      messages: [{ role: "user", content: "the prompt text" }],
    });
    expect(typeof callArgs?.max_tokens).toBe("number");
    expect(callArgs?.max_tokens ?? 0).toBeGreaterThan(0);
  });

  it("generate() passes a bounded numeric timeout as the second (request options) argument, guarding against a hung provider", async () => {
    chatCompletionsCreateMock.mockResolvedValue({ choices: [{ message: { content: "ok" } }] });
    const adapter = new OpenAIAdapter("x");

    await adapter.generate("the prompt text");

    const requestOptions = chatCompletionsCreateMock.mock.calls[0]?.[1] as
      | { timeout?: number }
      | undefined;
    expect(typeof requestOptions?.timeout).toBe("number");
    expect(requestOptions?.timeout ?? 0).toBeGreaterThan(0);
  });

  it("generate() degrades to '' when the stubbed SDK throws (graceful degradation, T-07-04)", async () => {
    chatCompletionsCreateMock.mockRejectedValue(new Error("network unavailable"));
    const adapter = new OpenAIAdapter("x");

    const result = await adapter.generate("prompt");

    expect(result).toBe("");
  });

  it("generate() degrades to '' when the stubbed SDK throws synchronously", async () => {
    chatCompletionsCreateMock.mockImplementation(() => {
      throw new Error("synchronous failure");
    });
    const adapter = new OpenAIAdapter("x");

    await expect(adapter.generate("prompt")).resolves.toBe("");
  });
});
