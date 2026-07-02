/**
 * Phase 5 FP-suppression fixture (ROADMAP criterion 4): every detector skips
 * the __tests__/ path segment, so this file deliberately contains the EXACT
 * patterns that WOULD fire SEC-01, BUNDLE-01, and INJECT-01 anywhere else in
 * a repo — and must yield ZERO findings here because this whole fixture's
 * only JS/TS file lives under __tests__/.
 */
import React from "react";

// Would trip SEC-01 (Stripe live-secret-key regex) outside __tests__/.
export const fakeStripeSecretKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

// Would trip BUNDLE-01 (NEXT_PUBLIC_-prefixed secret-keyword env var) outside __tests__/.
export const fakeExposedSecret = process.env.NEXT_PUBLIC_SECRET;

// Would trip INJECT-01 (unsanitized dangerouslySetInnerHTML) outside __tests__/.
export function FakeUnsafeComponent({ rawHtml }: { rawHtml: string }) {
  return <div dangerouslySetInnerHTML={{ __html: rawHtml }} />;
}

void React;
