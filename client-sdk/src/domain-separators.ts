export const DOM_PADDING = 1347436868n;
export const DOM_NULLIFIER = 1346917708n;
export const DOM_ESCROW = 1346720579n;
export const DOM_ENC = 1346719299n;
export const DOM_AUDIT_TAG = 1346458695n;
export const DOM_OUTPUT_NOTE_TAG = 1347310663n;
export const DOM_COMMITMENT_V3 = 1346582067n;
export const DOM_NULLIFIER_V3 = 1346917939n;
export const DOM_SPEND_AUTH_V3 = 1347696179n;
export const DOM_SPEND_INTENT_V3 = 1346787891n;

export const BABYJUB_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

/**
 * Map any integer into `(0, l)` so it satisfies circom `LessThan(252)` vs
 * `BABYJUB_SUBGROUP_ORDER` and `BabyPbk`. Values already in range are unchanged.
 */
export function canonicalBabyJubScalarFromInteger(value: bigint): bigint {
  if (value > 0n && value < BABYJUB_SUBGROUP_ORDER) {
    return value;
  }
  return (value % (BABYJUB_SUBGROUP_ORDER - 1n)) + 1n;
}
