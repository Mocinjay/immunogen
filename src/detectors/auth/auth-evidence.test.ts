import { describe, expect, it } from "vitest";

import { isPublicByNaturePath } from "./auth-evidence.js";

describe("isPublicByNaturePath", () => {
  it.each([
    ["api/health"],
    ["api/login"],
    ["api/auth/[...nextauth]"],
    ["api/verify-otp"],
    ["api/forgot-password"],
    ["api/auth/2fa"],
    ["api/auth/two-factor/verify"],
    ["api/sign-in/mfa"],
  ])("%s is public by nature", (path) => {
    expect(isPublicByNaturePath(path.split("/"))).toBe(true);
  });

  it.each([
    ["api/settings/2fa"],
    ["api/account/mfa"],
    ["api/user/otp"],
    ["api/auth/2fa/disable"],
    ["api/auth/mfa/setup"],
    ["api/two-factor"],
    ["api/users"],
  ])("%s is not", (path) => {
    expect(isPublicByNaturePath(path.split("/"))).toBe(false);
  });
});
