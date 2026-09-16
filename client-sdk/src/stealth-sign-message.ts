/** Default nonce when deriving the wallet sign-in message. */
export const DEFAULT_STEALTH_SIGN_NONCE = 'main address';

/** Domain tag mixed into the spend-scalar digest (H6). */
export const SPEND_SCALAR_DOMAIN_TAG = 'privacy-pool-spend-scalar-v1';

/** Schema version bound into the spend-scalar message and digest. */
export const OWNER_BOUND_NOTE_SCHEMA_VERSION = 1;

export type SpendScalarDomain = {
  networkPassphrase: string;
  poolContract: string;
  registryContract: string;
  schemaVersion?: number;
};

export function resolveSpendScalarSchemaVersion(domain: SpendScalarDomain): number {
  return domain.schemaVersion ?? OWNER_BOUND_NOTE_SCHEMA_VERSION;
}

/**
 * Plaintext for Stellar wallet message signing (spend-key derivation).
 * Sign the exact bytes of this string (UTF-8) with the stellar account key.
 *
 * The derived scalar is the owner-bound spend key for notes in this environment.
 */
export function buildStealthAddressSignMessage(
  address: string,
  domain: SpendScalarDomain,
  nonce: string = DEFAULT_STEALTH_SIGN_NONCE,
): string {
  const schemaVersion = resolveSpendScalarSchemaVersion(domain);
  return [
    'Arcane privacy layer: derive your private-note spend key.',
    '',
    `Wallet: ${address}`,
    `Network: ${domain.networkPassphrase}`,
    `Pool: ${domain.poolContract}`,
    `Registry: ${domain.registryContract}`,
    `Schema: owner-bound-note-v${schemaVersion}`,
    `Nonce: ${nonce}`,
    '',
    'This signature derives the key that authorizes spending your private notes in this environment.',
  ].join('\n');
}
