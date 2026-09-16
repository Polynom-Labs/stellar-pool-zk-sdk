import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";
import alias from "@rollup/plugin-alias";
import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";

const nodeBuiltins = [
  "fs",
  "path",
  "url",
  "crypto",
  "os",
  "stream",
  "util",
  "worker_threads",
];
const __dirname = path.dirname(fileURLToPath(import.meta.url));

let wasmPackDone = false;

function wasmPack() {
  return {
    name: "wasm-pack",
    buildStart() {
      if (wasmPackDone) return;
      wasmPackDone = true;
      const crateDir = path.join(__dirname, "crate");
      const result = spawnSync(
        "wasm-pack",
        ["build", "--target", "web", "--out-dir", "../pkg"],
        { cwd: crateDir, stdio: "inherit", shell: true },
      );
      if (result.status !== 0) {
        throw new Error(`wasm-pack exited with code ${result.status}`);
      } else {
        fs.rmSync(path.join(__dirname, "pkg", ".gitignore"));
        fs.rmSync(path.join(__dirname, "pkg", "package.json"));
      }
    },
  };
}

function readCircuitsManifestJson() {
  if (process.env.ZK_CIRCUITS_MANIFEST_JSON) {
    return process.env.ZK_CIRCUITS_MANIFEST_JSON;
  }
  for (const rel of [
    ["..", "artifacts", "circuits-manifest.json"],
    ["..", "artifacts", "zk-rebuild-plan.json"],
  ]) {
    const manifestPath = path.join(__dirname, ...rel);
    if (!fs.existsSync(manifestPath)) {
      continue;
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      const circuits = parsed.circuits;
      if (circuits && typeof circuits === "object") {
        const slim = {};
        for (const [stem, meta] of Object.entries(circuits)) {
          if (meta && typeof meta === "object" && "version" in meta) {
            slim[stem] = {
              version: String(meta.version),
              kind: meta.kind,
            };
          }
        }
        return JSON.stringify(slim);
      }
    } catch {
      /* try next */
    }
  }
  return "{}";
}

function injectZkArtifactBuildParams() {
  const version = JSON.parse(
    fs.readFileSync(path.join(__dirname, "package.json"), "utf8"),
  ).version;
  const cdnOrigin = (process.env.ZK_ARTIFACT_CDN_ORIGIN ?? "")
    .trim()
    .replace(/\/+$/, "");
  const manifestJson = readCircuitsManifestJson();
  let mainVersion = version;
  try {
    const parsed = JSON.parse(manifestJson);
    if (parsed.main?.version) {
      mainVersion = String(parsed.main.version).replace(/^v/, "");
    }
  } catch {
    /* package version */
  }
  const defaultBaseUrl = cdnOrigin
    ? `${cdnOrigin}/stellar/${mainVersion}`
    : `https://github.com/Polynom-Labs/stellar-pool-zk-sdk/releases/download/v${mainVersion}`;
  return {
    name: "inject-zk-artifact-build-params",
    transform(code, id) {
      if (!id.replaceAll("\\", "/").endsWith("zk-artifact-url.ts")) {
        return null;
      }
      return {
        code: code
          .replaceAll("__ZK_SDK_PACKAGE_VERSION__", version)
          .replaceAll("__ZK_ARTIFACT_CDN_ORIGIN__", cdnOrigin)
          .replaceAll("__ZK_DEFAULT_ARTIFACT_BASE_URL__", defaultBaseUrl)
          .replaceAll(
            "__ZK_CIRCUITS_MANIFEST_JSON__",
            JSON.stringify(manifestJson).slice(1, -1),
          ),
        map: null,
      };
    },
  };
}

function sdkPlugins(options) {
  return [
    alias({
      entries: [
        { find: "privacy-pool-client-sdk", replacement: __dirname },
        ...(options.browserCache
          ? [
              {
                find: /[/\\]fetch-artifact\.ts$/,
                replacement: path.join(
                  __dirname,
                  "src/fetch-artifact.browser.ts",
                ),
              },
            ]
          : []),
      ],
    }),
    wasmPack(),
    injectZkArtifactBuildParams(),
    typescript({
      tsconfig: "./tsconfig.json",
      declaration: options.declarations,
      declarationDir: options.declarations ? "dist" : undefined,
    }),
    resolve({
      browser: options.browserCache,
      preferBuiltins: !options.browserCache,
    }),
    commonjs(),
    json(),
  ];
}

const browserSdkConfig = {
  input: "src/index.ts",
  output: {
    dir: "dist",
    format: "es",
    sourcemap: true,
    entryFileNames: "index.mjs",
    chunkFileNames: "[name]-[hash].mjs",
  },
  external: [
    "@stellar/stellar-sdk",
    "circomlibjs",
    "ffjavascript",
    ...nodeBuiltins,
  ],
  plugins: sdkPlugins({ browserCache: true, declarations: true }),
};

const nodeSdkConfig = {
  input: "src/index.ts",
  output: {
    dir: "dist",
    format: "es",
    sourcemap: true,
    entryFileNames: "index.node.mjs",
    chunkFileNames: "[name]-node-[hash].mjs",
  },
  external: [
    "@stellar/stellar-sdk",
    "circomlibjs",
    "ffjavascript",
    ...nodeBuiltins,
  ],
  plugins: sdkPlugins({ browserCache: false, declarations: false }),
};

const cliConfig = {
  input: "src/cli.ts",
  output: {
    dir: "dist",
    format: "cjs",
    sourcemap: true,
    banner: "#!/usr/bin/env node",
    entryFileNames: "cli.js",
    chunkFileNames: "[name]-[hash].js",
  },
  external: [
    "@stellar/stellar-sdk",
    "circomlibjs",
    "ffjavascript",
    ...nodeBuiltins,
  ],
  plugins: [
    alias({
      entries: [{ find: "privacy-pool-client-sdk", replacement: __dirname }],
    }),
    wasmPack(),
    injectZkArtifactBuildParams(),
    typescript({
      tsconfig: "./tsconfig.json",
      declaration: false,
    }),
    resolve({ preferBuiltins: true }),
    commonjs(),
    json(),
  ],
};

export default [browserSdkConfig, nodeSdkConfig, cliConfig];
