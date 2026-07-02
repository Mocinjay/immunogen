import { defineConfig } from "tsup";

export default defineConfig([
  // Library: dual ESM + CJS build with type declarations.
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    outDir: "dist",
    sourcemap: true,
    clean: true,
  },
  // CLI bin: ESM-only, executable via shebang banner.
  {
    entry: { immunogen: "bin/immunogen.ts" },
    format: ["esm"],
    dts: false,
    outDir: "dist",
    sourcemap: true,
    clean: false,
    banner: {
      js: "#!/usr/bin/env node",
    },
  },
]);
