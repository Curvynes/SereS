import { build } from "esbuild";
import { copyFile, mkdir } from "node:fs/promises";

const wasmOutput = "../public/pkg/matrix_sdk_crypto_wasm_bg.wasm";
const licenseOutput = "../public/licenses";
await mkdir("../public/pkg", { recursive: true });
await mkdir(licenseOutput, { recursive: true });
await copyFile(
  "node_modules/@matrix-org/matrix-sdk-crypto-wasm/pkg/matrix_sdk_crypto_wasm_bg.wasm",
  wasmOutput,
);
await copyFile("node_modules/matrix-js-sdk/LICENSE", `${licenseOutput}/matrix-js-sdk-LICENSE`);
await copyFile("node_modules/@matrix-org/matrix-sdk-crypto-wasm/LICENSE", `${licenseOutput}/matrix-sdk-crypto-wasm-LICENSE`);

await build({
  entryPoints: ["../frontend/matrix.ts"],
  bundle: true,
  platform: "browser",
  format: "esm",
  target: ["es2020"],
  loader: { ".wasm": "file" },
  assetNames: "assets/[name]-[hash]",
  nodePaths: ["./node_modules"],
  outfile: "../public/matrix.js",
});
