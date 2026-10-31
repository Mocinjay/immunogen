import { describe, expect, it } from "vitest";

import { NoopAdapter } from "./noop.js";

describe("NoopAdapter — mandatory zero-setup default", () => {
  it("generate() resolves to an empty string", async () => {
    const adapter = new NoopAdapter();

    const result = await adapter.generate("any prompt");

    expect(result).toBe("");
  });

  it("declares name === 'noop'", () => {
    const adapter = new NoopAdapter();

    expect(adapter.name).toBe("noop");
  });
});
