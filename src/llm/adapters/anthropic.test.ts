import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Minimal shape of the arguments AnthropicAdapter.generate() passes to
 * `messages.create` — typed explicitly (rather than importing the real
 * SDK's MessageCreateParamsBase) so this fully-stubbed suite stays
 * decoupled from the real SDK's type surface while avoiding an unsafe
 * `any` on `mock.calls[0]?.[0]` member access.
 */
interface FakeMessagesCreateArgs {
  max_tokens: number;
  messages: Array<{ role: string; content: string }>;
}

// The @anthropic-ai/sdk client is stubbed at the module boundary so this
// suite NEVER performs a real network call or requires a real API key
// (per the project's offline-deterministic test mandate). The fake
// constructor records the options it was called with so tests can assert
// on them, and its `messages.create` is a mock the tests configure per
// case.
const messagesCreateMock =
  vi.fn<(args: FakeMessagesCreateArgs, options?: { timeout?: number }) => Promise<unknown>>();
const anthropicConstructorMock = vi.fn();

vi.mock("@anthropic-ai/sdk", () => ({
  default: class FakeAnthropic {
    messages = { create: messagesCreateMock };
    constructor(options: unknown) {
      anthropicConstructorMock(options);
    }
  },
}));

const { AnthropicAdapter } = await import("./anthropic.js");

afterEach(() => {
  messagesCreateMock.mockReset();
  anthropicConstructorMock.mockReset();
});

describe("AnthropicAdapter", () => {
  it("declares name === 'anthropic'", () => {
    const adapter = new AnthropicAdapter("sk-ant-test");

    expect(adapter.name).toBe("anthropic");
  });

  it("passes the apiKey through to the Anthropic client constructor", () => {
    void new AnthropicAdapter("sk-ant-test-key");

    expect(anthropicConstructorMock).toHaveBeenCalledWith({ apiKey: "sk-ant-test-key" });
  });

  it("generate() returns the concatenated text of the response content blocks", async () => {
    messagesCreateMock.mockResolvedValue({
      content: [
        { type: "text", text: "Fix the SQL injection by using " },
        { type: "text", text: "parameterized queries." },
      ],
    });
    const adapter = new AnthropicAdapter("sk-ant-test");

    const result = await adapter.generate("How do I fix this finding?");

    expect(result).toBe("Fix the SQL injection by using parameterized queries.");
    expect(messagesCreateMock).toHaveBeenCalledTimes(1);
  });

  it("generate() ignores non-text content blocks", async () => {
    messagesCreateMock.mockResolvedValue({
      content: [
        { type: "text", text: "Only this." },
        { type: "tool_use", id: "x", name: "y", input: {} },
      ],
    });
    const adapter = new AnthropicAdapter("sk-ant-test");

    const result = await adapter.generate("prompt");

    expect(result).toBe("Only this.");
  });

  it("generate() calls messages.create with the prompt as a single user message and a bounded max_tokens", async () => {
    messagesCreateMock.mockResolvedValue({ content: [{ type: "text", text: "ok" }] });
    const adapter = new AnthropicAdapter("sk-ant-test");

    await adapter.generate("the prompt text");

    const callArgs = messagesCreateMock.mock.calls[0]?.[0];
    expect(callArgs).toMatchObject({
      messages: [{ role: "user", content: "the prompt text" }],
    });
    expect(typeof callArgs?.max_tokens).toBe("number");
    expect(callArgs?.max_tokens ?? 0).toBeGreaterThan(0);
  });

  it("generate() passes a bounded numeric timeout as the second (request options) argument, guarding against a hung provider", async () => {
    messagesCreateMock.mockResolvedValue({ content: [{ type: "text", text: "ok" }] });
    const adapter = new AnthropicAdapter("sk-ant-test");

    await adapter.generate("the prompt text");

    const requestOptions = messagesCreateMock.mock.calls[0]?.[1] as { timeout?: number } | undefined;
    expect(typeof requestOptions?.timeout).toBe("number");
    expect(requestOptions?.timeout ?? 0).toBeGreaterThan(0);
  });

  it("generate() degrades to '' when the stubbed SDK throws (graceful degradation, T-07-04)", async () => {
    messagesCreateMock.mockRejectedValue(new Error("network unavailable"));
    const adapter = new AnthropicAdapter("sk-ant-test");

    const result = await adapter.generate("prompt");

    expect(result).toBe("");
  });

  it("generate() degrades to '' when the stubbed SDK throws synchronously", async () => {
    messagesCreateMock.mockImplementation(() => {
      throw new Error("synchronous failure");
    });
    const adapter = new AnthropicAdapter("sk-ant-test");

    await expect(adapter.generate("prompt")).resolves.toBe("");
  });
});
