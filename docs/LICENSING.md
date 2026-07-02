# Licensing Policy

This document explains immunogen's licensing model: why the project is MIT,
how third-party Apache-2.0 code is reused safely, and what every contributor
must do when adapting code from an upstream project.

## 1. Project license

Immunogen as a whole is licensed under the **MIT License** (see
[LICENSE](../LICENSE) at the repo root). MIT is maximally permissive and is
the right default for an open-source CLI/library aimed at broad adoption.

An MIT project may legally include components licensed under more
restrictive-but-still-permissive terms, such as Apache-2.0, as long as that
component's own license obligations are met. Apache-2.0's obligations are
satisfied by retaining copyright/license notices (§4(c)) and, where the
upstream project ships a NOTICE file, reproducing its attribution content
(§4(d)). See [NOTICE](../NOTICE) and
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for how immunogen
discharges those obligations for NVIDIA SkillSpector.

## 2. SPDX header convention for adapted source files

Every source file that is **adapted** (ported, transliterated, or copied
with modification) from an Apache-2.0-licensed upstream — currently this
means [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) — MUST
begin with two SPDX header lines, reproduced exactly (only the comment
syntax changes per language):

```
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
```

For example, in a TypeScript file the header is two `//` comment lines at
the very top of the file, before any imports:

```
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
```

Do not paraphrase, reword, or abbreviate the copyright line. Copy it
character-for-character from this document or from an existing SkillSpector
source file. The license identifier (`Apache-2.0`) must use the exact SPDX
license expression, not a free-text description.

This convention is documented here ahead of any actual code adaptation —
no SkillSpector code is adapted as of Phase 1. The first files to carry
this header will be the AI-layer detectors (CAT-11) in Phase 6, when
SkillSpector's pattern logic is ported to TypeScript. A CI lint or grep
check enforcing this header on any newly-added file under
`src/detectors/ai-layer/` (or equivalent) should be added at that time.

## 3. Gitleaks regex patterns — independently-expressed reuse

[gitleaks](https://github.com/gitleaks/gitleaks) ships secret-detection
regex rules under an MIT-compatible license for the engine, but the
patterns themselves are facts about how secrets are formatted (e.g., "a
Stripe live key starts with `sk_live_`") and are not independently
copyrightable expression. Immunogen may **re-express** gitleaks-style
detection logic as its own independently-written regex rules without
requiring an SPDX header, provided the implementation is written fresh
(not copy-pasted) from the pattern's public description.

Immunogen must **not** bundle the `gitleaks-action` distribution directly —
that component changed to a commercial license at v2.0.0 and is out of
scope for reuse regardless of how the underlying regex patterns are
treated.

If a future contribution ever copies gitleaks rule *source* verbatim
(rather than re-deriving the pattern), it must be treated as an adapted
file under §2 above and carry the appropriate SPDX header for whatever
license that source carries at the time.

## 4. Semgrep-maintained rules — do not bundle

Semgrep's open-source **engine** is LGPL-2.1, which is fine to link
against. Semgrep's **maintained rule packs** (the registry rules under
`p/owasp-top-ten` and similar), however, are distributed under the
[Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license),
which restricts use to internal business purposes and explicitly
prohibits redistribution in a competing tool or SaaS offering. Immunogen,
as a competing static-analysis scanner, MUST NOT bundle, vendor, or
ship any Semgrep-maintained rule YAML.

Equivalent detection logic must instead be written in-house as
`@babel/traverse` visitors, informed by — but not copied from —
publicly documented vulnerability patterns (the same approach used for
gitleaks in §3). `eslint-plugin-security` (Apache-2.0) may be referenced
for inspiration since its rule *logic*, not Semgrep's rule *YAML*, is
permissively licensed.

## 5. Automated enforcement

`npx license-checker` runs in CI (introduced in Plan 04 of this phase) as
the automated gate against the npm dependency tree: it fails the build if
a new runtime dependency introduces a GPL-family or otherwise
redistribution-incompatible license. `license-checker` enforces the
**dependency** license surface; it does not (and cannot) detect missing
SPDX headers on adapted source files — that is a manual review
requirement under §2 until a dedicated grep-based CI check is added in
Phase 6 alongside the first adapted SkillSpector files.
