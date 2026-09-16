import assert from "node:assert/strict";
import {
  defaultZkArtifactBaseUrl,
  defaultZkArtifactFileUrls,
  parsedCircuitsManifest,
  versionForStem,
  zkArtifactFileUrl,
  ZK_ARTIFACT_CDN_ORIGIN,
  ZK_DEFAULT_ARTIFACT_BASE_URL,
  ZK_ARTIFACT_CDN_PREFIX,
  ZK_ARTIFACT_GITHUB_REPO,
  ZK_ARTIFACT_VERSION,
  ZK_CDN_PROVING_ARTIFACT_FILES,
  ZK_CIRCUITS_MANIFEST_JSON,
  ZK_SDK_PACKAGE_VERSION,
} from "../dist/index.mjs";

function expectedBase(version) {
  const tag = version.startsWith("v") ? version.slice(1) : version;
  const origin = ZK_ARTIFACT_CDN_ORIGIN.trim().replace(/\/+$/, "");
  if (origin.length > 0) {
    return `${origin}/${ZK_ARTIFACT_CDN_PREFIX}/${tag}`;
  }
  return `https://github.com/${ZK_ARTIFACT_GITHUB_REPO}/releases/download/v${tag}`;
}

assert.equal(defaultZkArtifactBaseUrl("0.8.0"), expectedBase("0.8.0"));
assert.equal(defaultZkArtifactBaseUrl("v1.2.3"), expectedBase("v1.2.3"));
assert.equal(defaultZkArtifactBaseUrl(), expectedBase(ZK_ARTIFACT_VERSION));
assert.equal(ZK_DEFAULT_ARTIFACT_BASE_URL, expectedBase(ZK_ARTIFACT_VERSION));
assert.notEqual(ZK_ARTIFACT_VERSION, "__ZK_ARTIFACT_VERSION__");
assert.notEqual(
  ZK_DEFAULT_ARTIFACT_BASE_URL,
  "__ZK_DEFAULT_ARTIFACT_BASE_URL__",
);
assert.equal(typeof ZK_SDK_PACKAGE_VERSION, "string");

const files = defaultZkArtifactFileUrls();
const base = expectedBase(ZK_ARTIFACT_VERSION);
assert.equal(ZK_CDN_PROVING_ARTIFACT_FILES.length, 12);
for (const fileName of ZK_CDN_PROVING_ARTIFACT_FILES) {
  assert.equal(files[fileName], `${base}/${fileName}`);
  assert.equal(fileName.includes("verification_key"), false);
}

assert.equal(ZK_ARTIFACT_GITHUB_REPO, "Polynom-Labs/stellar-pool-zk-sdk");
assert.equal(typeof parsedCircuitsManifest(), "object");
assert.equal(typeof ZK_CIRCUITS_MANIFEST_JSON, "string");
assert.doesNotMatch(ZK_CIRCUITS_MANIFEST_JSON, /^__ZK_/);
assert.equal(versionForStem("main"), parsedCircuitsManifest().main?.version
  ? parsedCircuitsManifest().main.version.replace(/^v/, "")
  : ZK_SDK_PACKAGE_VERSION);
assert.equal(
  zkArtifactFileUrl("main_delegated.graph.bin"),
  `${expectedBase(versionForStem("main_delegated"))}/main_delegated.graph.bin`,
);
assert.equal(
  zkArtifactFileUrl("main_6x6_delegated_proving_key.bin"),
  `${expectedBase(versionForStem("main_6x6_delegated"))}/main_6x6_delegated_proving_key.bin`,
);

console.log("zk-artifact-url: ok");
