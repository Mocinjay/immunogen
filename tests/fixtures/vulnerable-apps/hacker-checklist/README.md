# hacker-checklist (vulnerable fixture)

One file per attack from the 14-item "What a HACKER tries on your vibe coded app" checklist. Every secret is fabricated.

| # | Attack | File | Expected rule |
|---|---|---|---|
| 1 | Script in your username | `lib/profile-card.ts` | INJECT-01 |
| 2 | Change the ID in the URL | `app/account/page.tsx` | AUTH-08 |
| 3 | Type /admin | `app/admin/page.tsx`, `app/api/admin/users/route.ts` | AUTH-09 |
| 4 | API key in the browser | `components/ChatWidget.tsx` | BUNDLE-01 / BUNDLE-02 |
| 5 | Prompt-inject your AI | `app/api/support/route.ts` | AILAYER-07 |
| 6 | Admin at signup | `app/api/signup/route.ts` | AUTH-10 |
| 7 | Edit the price | `app/api/checkout/route.ts` | PAY-03 |
| 8 | Fake a payment | `app/api/orders/[id]/paid/route.ts` | PAY-04 |
| 9 | Redeem it 100 times | `app/api/cart/coupon/route.ts` | PAY-05 |
| 10 | Order -1 items | `app/api/cart/route.ts` | PAY-06 |
| 11 | Guess the login code | `app/api/auth/verify-code/route.ts`, `lib/otp.ts` | RATE-01, AUTH-11 |
| 12 | Query your database | `app/api/products/search/route.ts` | INJECT-02 |
| 13 | .env in Git | `.env` | SEC-05 |
| 14 | Upload a non-photo | `app/api/avatar/route.ts` | UPLOAD-01 |
