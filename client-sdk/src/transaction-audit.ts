import {
  randomFrDecimal253,
  type DepositObject,
  type DepositSlot,
  type WithdrawObject,
  type WithdrawSlot,
} from "./withdrawal-transaction-input";

export const TRANSACTION_N_AUDIT_SLOTS = 4;
export const SIX_BY_SIX_N_AUDIT_SLOTS = 12;
export const TEN_BY_ONE_N_AUDIT_SLOTS = 11;
export const DEFAULT_APPLICATION_ID = "101";

/** BabyJub audit public key (decimal Fr) used in BDD / local demo when env is unset. */
export const DEMO_AUDIT_PUBLIC_KEY: AuditPublicKey = [
  "21605515851820432880964235241069234202284600780825340516808373216881770219365",
  "18856460861531942120859708048677603751294231190189224157283439874962410808705",
];

export type AuditPublicKey = [string, string];

export interface TransactionAuditParams {
  applicationId: string;
  noteAuditPublicKey: AuditPublicKey;
  auditEphemeralScalar: string;
}

export interface TransactionSlotApplicationIds {
  inputApplicationIds: string[];
  outputApplicationIds: string[];
}

function isActiveWithdraw(slot: WithdrawObject): boolean {
  return slot.value !== "0";
}

function isActiveDeposit(slot: DepositObject): boolean {
  return slot.value !== "0";
}

function resolveWithdrawSlot(slot: WithdrawSlot): WithdrawObject | null {
  if (slot === "dummy") {
    return null;
  }
  return slot;
}

function resolveDepositSlot(slot: DepositSlot): DepositObject | null {
  if (slot === "dummy") {
    return null;
  }
  return slot;
}

export function buildUniformAuditParams(
  applicationId: string = DEFAULT_APPLICATION_ID,
  auditPublicKey: AuditPublicKey,
  _nAuditSlots: number = TRANSACTION_N_AUDIT_SLOTS,
): TransactionAuditParams {
  return {
    applicationId,
    noteAuditPublicKey: auditPublicKey,
    auditEphemeralScalar: randomFrDecimal253(),
  };
}

export function resolveSlotApplicationIds(
  audit: TransactionAuditParams,
  withdrawSlots: WithdrawSlot[],
  depositSlots: DepositSlot[],
): TransactionSlotApplicationIds {
  return {
    inputApplicationIds: withdrawSlots.map((slot) => {
      const resolved = resolveWithdrawSlot(slot);
      return resolved && isActiveWithdraw(resolved) ? audit.applicationId : "0";
    }),
    outputApplicationIds: depositSlots.map((slot) => {
      const resolved = resolveDepositSlot(slot);
      return resolved && isActiveDeposit(resolved) ? audit.applicationId : "0";
    }),
  };
}

export function withApplicationIdOnDeposit(
  deposit: DepositObject,
  applicationId: string,
): DepositObject {
  return { ...deposit, applicationId };
}

export function withApplicationIdOnWithdraw(
  withdraw: WithdrawObject,
  applicationId: string,
): WithdrawObject {
  return { ...withdraw, applicationId };
}

/**
 * Prefer an explicit key, then `NOTE_AUDIT_PUBLIC_KEY_X`/`_Y` env (decimal Fr),
 * then the built-in demo key. Used by CLI/`demo.sh` for per-app audit pubkeys.
 */
export function resolveAuditPublicKeyFromEnv(
  auditPublicKey?: AuditPublicKey,
): AuditPublicKey {
  if (auditPublicKey) {
    return auditPublicKey;
  }
  const x = process.env.NOTE_AUDIT_PUBLIC_KEY_X?.trim();
  const y = process.env.NOTE_AUDIT_PUBLIC_KEY_Y?.trim();
  if (x && y) {
    return [x, y];
  }
  return DEMO_AUDIT_PUBLIC_KEY;
}

export function resolveTransactionAuditParams(
  applicationId: string,
  auditPublicKey?: AuditPublicKey,
  nAuditSlots: number = TRANSACTION_N_AUDIT_SLOTS,
): TransactionAuditParams {
  return buildUniformAuditParams(
    applicationId,
    resolveAuditPublicKeyFromEnv(auditPublicKey),
    nAuditSlots,
  );
}
