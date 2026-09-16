import type { DecodedDepositorSharedSecretPreimage, DecodedEphemeralKey } from './ephemeral-key';
import type { DecodedRecipientSharedSecretPreimage, Hex } from './stealth-address';

/** ECDH shared key coordinates (`ecdh_shared_key` / circuit `ECDH` output). */
export interface SharedSecret {
  x: Hex;
  y: Hex;
}

/** Withdrawer-side material: recipient private scalar ‖ depositor’s ephemeral point. */
export interface DecodedWithdrawerSharedSecret {
  recipientScalar: Hex;
  ephemeralKey: DecodedEphemeralKey;
}

export type EcdhSharedKeyFn = (
  privHex64: string,
  pubXHex64: string,
  pubYHex64: string,
) => { x: string; y: string };

/**
 * Depositor: `randomNonceScalar * recipientStealthPoint` (same as circom `ECDH` with depositor scalar).
 */
export function sharedSecretFromDepositorPreimage(
  ecdhShared: EcdhSharedKeyFn,
  preimage: DecodedDepositorSharedSecretPreimage,
): SharedSecret {
  const out = ecdhShared(
    preimage.randomNonceScalar,
    preimage.recipientStealthAddress.x,
    preimage.recipientStealthAddress.y,
  );
  return { x: out.x, y: out.y };
}

/**
 * Recipient: `recipientScalar * ephemeralKey` (same shared point as depositor path when keys match).
 */
export function sharedSecretFromRecipientPreimage(
  ecdhShared: EcdhSharedKeyFn,
  preimage: DecodedRecipientSharedSecretPreimage,
): SharedSecret {
  const out = ecdhShared(
    preimage.recipientScalar,
    preimage.ephemeralKey.x,
    preimage.ephemeralKey.y,
  );
  return { x: out.x, y: out.y };
}
