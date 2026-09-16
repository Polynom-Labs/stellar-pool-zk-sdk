import { ZK_SDK_PACKAGE_VERSION } from "./zk-artifact-url";

export const ZK_ARTIFACT_CACHE_NAME = `stellar-privacy-pool-zk-artifacts:${ZK_SDK_PACKAGE_VERSION}`;

const inflight = new Map<string, Promise<Uint8Array>>();

export async function fetchArtifact(url: string): Promise<Uint8Array> {
  const pending = inflight.get(url);
  if (pending) {
    return pending;
  }
  const promise = readArtifact(url).finally(() => {
    inflight.delete(url);
  });
  inflight.set(url, promise);
  return promise;
}

async function readArtifact(url: string): Promise<Uint8Array> {
  const cache = await openArtifactCache();
  if (cache) {
    const cached = await cache.match(url);
    if (cached?.ok) {
      return new Uint8Array(await cached.arrayBuffer());
    }
  }
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${String(response.status)}`);
  }
  if (cache) {
    try {
      await cache.put(url, response.clone());
    } catch {
      // Quota or private mode: still return the downloaded bytes.
    }
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function openArtifactCache(): Promise<Cache | undefined> {
  if (typeof caches === "undefined") {
    return undefined;
  }
  return caches.open(ZK_ARTIFACT_CACHE_NAME);
}
