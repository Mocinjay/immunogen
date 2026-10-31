import { readFileSync } from "node:fs";

import { defineConfig } from "tsup";

const { version } = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as { version: string };

/** Build-time constants (see src/version.ts). */
const define = { __IMMUNOGEN_VERSION__: JSON.stringify(version) };

export default defineConfig([
  // Library: dual ESM + CJS build with type declarations.
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    outDir: "dist",
    sourcemap: true,
    clean: true,
    define,
  },
  // CLI bin: ESM-only, executable via shebang banner.
  {
    entry: { immunogen: "bin/immunogen.ts" },
    format: ["esm"],
    dts: false,
    outDir: "dist",
    sourcemap: true,
    clean: false,
    define,
    banner: {
      js: "#!/usr/bin/env node",
    },
  },
]);
