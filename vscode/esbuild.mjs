// Bundles the extension (dist/) and, with --tests, the unit tests (out-test/).
import { build, context } from "esbuild";
import { readdirSync } from "node:fs";

const args = new Set(process.argv.slice(2));

if (args.has("--tests")) {
  const entries = readdirSync("test").filter((f) => f.endsWith(".test.ts")).map((f) => `test/${f}`);
  await build({
    entryPoints: entries,
    outdir: "out-test",
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node18",
    outExtension: { ".js": ".cjs" },
    logLevel: "warning",
  });
} else {
  const opts = {
    entryPoints: ["src/extension.ts"],
    outfile: "dist/extension.js",
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node18",
    external: ["vscode"],
    minify: args.has("--production"),
    sourcemap: !args.has("--production"),
    logLevel: "info",
  };
  if (args.has("--watch")) await (await context(opts)).watch();
  else await build(opts);
}
