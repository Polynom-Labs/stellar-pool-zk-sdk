export const ZK_ARTIFACT_GITHUB_REPO =
  "Polynom-Labs/stellar-pool-zk-sdk";

export const ZK_SDK_PACKAGE_VERSION = "__ZK_SDK_PACKAGE_VERSION__";

/** npm package version; per-stem CDN folders live in ZK_CIRCUITS_MANIFEST_JSON. */
export const ZK_ARTIFACT_VERSION = "__ZK_SDK_PACKAGE_VERSION__";

export const ZK_ARTIFACT_CDN_ORIGIN = "__ZK_ARTIFACT_CDN_ORIGIN__";

export const ZK_DEFAULT_ARTIFACT_BASE_URL = "__ZK_DEFAULT_ARTIFACT_BASE_URL__";

/** Injected at publish time: stem -> { version, kind, fingerprint? }. */
export const ZK_CIRCUITS_MANIFEST_JSON = "__ZK_CIRCUITS_MANIFEST_JSON__";

export type ZkCircuitManifestEntry = {
  version: string;
  kind?: string;
  fingerprint?: string;
  shapeId?: string;
};

export type ZkCircuitsManifest = Record<string, ZkCircuitManifestEntry>;

export function parsedCircuitsManifest(): ZkCircuitsManifest {
  if (
    ZK_CIRCUITS_MANIFEST_JSON.length === 0 ||
    ZK_CIRCUITS_MANIFEST_JSON.startsWith("__ZK_")
  ) {
    return {};
  }
  try {
    const parsed = JSON.parse(ZK_CIRCUITS_MANIFEST_JSON) as unknown;
    if (!parsed || typeof parsed !== "object") {
      return {};
    }
    return parsed as ZkCircuitsManifest;
  } catch {
    return {};
  }
}

export const ZK_ARTIFACT_CDN_PREFIX = "stellar";

export const ZK_CDN_PROVING_ARTIFACT_FILES = [
  "main.graph.bin",
  "main.r1cs.gz",
  "main_proving_key.bin",
  "main_6x6.graph.bin",
  "main_6x6.r1cs.gz",
  "main_6x6_proving_key.bin",
  "main_delegated.graph.bin",
  "main_delegated.r1cs.gz",
  "main_delegated_proving_key.bin",
  "main_6x6_delegated.graph.bin",
  "main_6x6_delegated.r1cs.gz",
  "main_6x6_delegated_proving_key.bin",
] as const;

export type ZkCdnProvingArtifactFile =
  (typeof ZK_CDN_PROVING_ARTIFACT_FILES)[number];

function artifactVersionTag(version: string): string {
  return version.startsWith("v") ? version.slice(1) : version;
}

function injectedCdnOrigin(): string {
  return ZK_ARTIFACT_CDN_ORIGIN.trim().replace(/\/+$/, "");
}

export function stemFromProvingFileName(fileName: string): string {
  return fileName
    .replace(/\.graph\.bin$/, "")
    .replace(/\.r1cs\.gz$/, "")
    .replace(/_proving_key\.bin$/, "")
    .replace(/_verification_key\.json$/, "")
    .replace(/_final\.zkey$/, "");
}

export function versionForStem(stem: string): string {
  const entry = parsedCircuitsManifest()[stem];
  if (entry?.version) {
    return artifactVersionTag(entry.version);
  }
  return artifactVersionTag(ZK_SDK_PACKAGE_VERSION);
}

export function zkArtifactBaseUrlForVersion(version: string): string {
  const tag = artifactVersionTag(version);
  const origin = injectedCdnOrigin();
  if (origin.length > 0) {
    return `${origin}/${ZK_ARTIFACT_CDN_PREFIX}/${tag}`;
  }
  if (
    !ZK_DEFAULT_ARTIFACT_BASE_URL.startsWith("__ZK_") &&
    ZK_DEFAULT_ARTIFACT_BASE_URL.includes(`/stellar/${tag}`)
  ) {
    return trimArtifactBaseUrl(ZK_DEFAULT_ARTIFACT_BASE_URL);
  }
  if (origin.length === 0 && !ZK_DEFAULT_ARTIFACT_BASE_URL.startsWith("__ZK_")) {
    const fallback = trimArtifactBaseUrl(ZK_DEFAULT_ARTIFACT_BASE_URL);
    if (fallback.length > 0) {
      return fallback.replace(/\/stellar\/[^/]+$/, `/stellar/${tag}`);
    }
  }
  return `https://github.com/${ZK_ARTIFACT_GITHUB_REPO}/releases/download/v${tag}`;
}

/** Package-level default (first published stem version or SDK version). */
export function defaultZkArtifactBaseUrl(version?: string): string {
  if (version) {
    return zkArtifactBaseUrlForVersion(version);
  }
  if (!ZK_DEFAULT_ARTIFACT_BASE_URL.startsWith("__ZK_")) {
    return trimArtifactBaseUrl(ZK_DEFAULT_ARTIFACT_BASE_URL);
  }
  return zkArtifactBaseUrlForVersion(ZK_SDK_PACKAGE_VERSION);
}

export function zkArtifactFileUrl(
  fileName: string,
  stem: string = stemFromProvingFileName(fileName),
): string {
  return `${zkArtifactBaseUrlForVersion(versionForStem(stem))}/${fileName}`;
}

export function defaultZkArtifactFileUrls(): Record<
  ZkCdnProvingArtifactFile,
  string
> {
  return Object.fromEntries(
    ZK_CDN_PROVING_ARTIFACT_FILES.map((fileName) => [
      fileName,
      zkArtifactFileUrl(fileName),
    ]),
  ) as Record<ZkCdnProvingArtifactFile, string>;
}

export function trimArtifactBaseUrl(value: string): string {
  let trimmed = value.trim();
  while (trimmed.endsWith("/")) {
    trimmed = trimmed.slice(0, -1);
  }
  return trimmed;
}
