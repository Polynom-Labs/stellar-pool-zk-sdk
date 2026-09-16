import { Keypair, TransactionBuilder, Operation, nativeToScVal, xdr, rpc, authorizeEntry } from '@stellar/stellar-sdk';
import {
  buildKytPassageAuthorization,
  derivePassageFromTransactContext,
  hashPublicSignalBytes,
  signatureBase64ToBytes,
  type InspectKytPassageRequest,
  type PublicLegContextInput,
} from './kyt-passage.js';

function addressToScVal(address: string): xdr.ScVal {
  return nativeToScVal(address, { type: 'address' });
}

export interface RegisterPassageParams {
  kytRegistryId: string;
  poolContract: string;
  owner: string;
  nonce?: bigint | number;
  publicSignalsBytes: Buffer | string;
  ciphertextBytes?: Buffer | string;
  publicLegContext: PublicLegContextInput;
  signature: string;
  expiresAtLedger: number;
  source: Keypair;
  networkPassphrase: string;
  rpcUrl: string;
}

export interface SubmitKytTransactParams {
  poolContract: string;
  owner: string;
  nonce: bigint | number;
  proofBytes: Buffer;
  publicSignalsBytes: Buffer;
  ciphertextBytes?: Buffer;
  /** Omit when the pool's own registered passage covers this call (no explicit signed authorization). */
  kytAuthorization?: { expirationLedger: number; signature: Buffer } | null;
  source: Keypair;
  networkPassphrase: string;
  rpcUrl: string;
}

export interface SubmitWithKytPassageParams extends SubmitKytTransactParams {
  kytRegistryId: string;
  kytSubmitHelperId?: string;
  inspectRequest: InspectKytPassageRequest;
  publicLegContext: PublicLegContextInput;
  inspectFn?: (request: InspectKytPassageRequest) => Promise<{
    passageId: string;
    signature: string;
    expiresAtLedger: number;
  }>;
}

export interface SubmitApprovedKytPassageParams extends SubmitKytTransactParams {
  kytSubmitHelperId: string;
  passageId: string;
  signature: string;
  expiresAtLedger: number;
}

export interface AtomicKytSubmitPlan {
  atomic: boolean;
  operations: Array<'helper.submit_with_passage' | 'register_passage' | 'pool.transact'>;
}

function passageIdHexToScVal(passageIdHex: string): xdr.ScVal {
  const bytes = Buffer.from(passageIdHex.replace(/^0x/, ''), 'hex');
  return xdr.ScVal.scvBytes(bytes);
}

function signatureToScVal(signature: Buffer): xdr.ScVal {
  return xdr.ScVal.scvBytes(signature);
}

function kytAuthorizationOptionToScVal(
  authorization: { expirationLedger: number; signature: Buffer } | null | undefined,
): xdr.ScVal {
  if (authorization === null || authorization === undefined) {
    return xdr.ScVal.scvVoid();
  }
  return nativeToScVal({
    expiration_ledger: authorization.expirationLedger,
    signature: authorization.signature,
  });
}

function registerPassageOperation(
  kytRegistryId: string,
  passageId: string,
  expiresAtLedger: number,
  signature: string,
): xdr.Operation {
  return Operation.invokeContractFunction({
    contract: kytRegistryId,
    function: 'register_passage',
    args: [
      passageIdHexToScVal(passageId),
      xdr.ScVal.scvU32(expiresAtLedger),
      signatureToScVal(signatureBase64ToBytes(signature)),
    ],
  });
}

function poolTransactOperation(params: SubmitKytTransactParams): xdr.Operation {
  return Operation.invokeContractFunction({
    contract: params.poolContract,
    function: 'transact',
    args: [
      addressToScVal(params.owner),
      nativeToScVal(params.nonce, { type: 'u64' }),
      xdr.ScVal.scvBytes(params.proofBytes),
      xdr.ScVal.scvBytes(params.publicSignalsBytes),
      xdr.ScVal.scvBytes(params.ciphertextBytes ?? Buffer.alloc(0)),
      kytAuthorizationOptionToScVal(params.kytAuthorization),
    ],
  });
}

function helperSubmitWithPassageOperation(
  helperContractId: string,
  params: SubmitKytTransactParams,
  passageId: string,
  expiresAtLedger: number,
  signature: string,
): xdr.Operation {
  return Operation.invokeContractFunction({
    contract: helperContractId,
    function: 'submit_with_passage',
    args: [
      addressToScVal(params.owner),
      nativeToScVal(params.nonce, { type: 'u64' }),
      xdr.ScVal.scvBytes(params.proofBytes),
      xdr.ScVal.scvBytes(params.publicSignalsBytes),
      passageIdHexToScVal(passageId),
      xdr.ScVal.scvU32(expiresAtLedger),
      signatureToScVal(signatureBase64ToBytes(signature)),
    ],
  });
}

async function submitTransaction(
  params: {
    source: Keypair;
    networkPassphrase: string;
    rpcUrl: string;
    fee: string;
    operations: xdr.Operation[];
    allowNonRootAuth?: boolean;
  },
): Promise<string> {
  const server = new rpc.Server(params.rpcUrl);
  const sourceAccount = await server.getAccount(params.source.publicKey());
  let builder = new TransactionBuilder(sourceAccount, {
    fee: params.fee,
    networkPassphrase: params.networkPassphrase,
  });
  for (const operation of params.operations) {
    builder = builder.addOperation(operation);
  }
  const tx = builder.setTimeout(300).build();
  const prepared = params.allowNonRootAuth
    ? await prepareTransactionAllowingNonRootAuth(
      server,
      params.rpcUrl,
      tx,
      params.source,
      params.networkPassphrase,
    )
    : await server.prepareTransaction(tx);
  prepared.sign(params.source);
  const result = await server.sendTransaction(prepared);
  const status = String(result.status);
  if (status !== 'PENDING' && status !== 'SUCCESS') {
    throw new Error(`transaction submit failed: ${status}`);
  }
  await waitForTransaction(server, result.hash);
  return result.hash;
}

async function prepareTransactionAllowingNonRootAuth(
  server: rpc.Server,
  rpcUrl: string,
  tx: ReturnType<TransactionBuilder['build']>,
  source: Keypair,
  networkPassphrase: string,
): Promise<ReturnType<TransactionBuilder['build']>> {
  const recording = await simulateTransactionRecordingNonRoot(rpcUrl, tx.toXDR());
  const validUntilLedgerSeq = recording.latestLedger + 1000;
  const signedAuth = await Promise.all(
    recording.auth.map((entry) => {
      if (
        entry.credentials().switch()
          === xdr.SorobanCredentialsType.sorobanCredentialsSourceAccount()
      ) {
        return entry;
      }
      return authorizeEntry(entry, source, validUntilLedgerSeq, networkPassphrase);
    }),
  );

  const invokeOp = tx.operations[0];
  if (tx.operations.length !== 1 || invokeOp.type !== 'invokeHostFunction') {
    throw new Error('Soroban transactions must contain exactly one invokeHostFunction operation');
  }

  const sourceAccount = await server.getAccount(source.publicKey());
  const signedTx = new TransactionBuilder(sourceAccount, {
    fee: tx.fee,
    networkPassphrase,
  })
    .addOperation(Operation.invokeHostFunction({
      func: invokeOp.func,
      auth: signedAuth,
      source: invokeOp.source,
    }))
    .setTimeout(300)
    .build();
  const enforcedSimulation = await server.simulateTransaction(signedTx);
  if (rpc.Api.isSimulationError(enforcedSimulation)) {
    throw new Error(`signed authorization simulation failed: ${enforcedSimulation.error}`);
  }
  return rpc.assembleTransaction(signedTx, enforcedSimulation).build();
}

async function simulateTransactionRecordingNonRoot(
  rpcUrl: string,
  transactionXdr: string,
): Promise<{ auth: xdr.SorobanAuthorizationEntry[]; latestLedger: number }> {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'simulateTransaction',
      params: {
        transaction: transactionXdr,
        authMode: 'record_allow_nonroot',
      },
    }),
  });
  const body = await response.json() as {
    error?: { message?: string };
    result?: {
      error?: string;
      latestLedger?: number;
      results?: Array<{ auth?: string[] }>;
    };
  };
  if (!response.ok || body.error) {
    throw new Error(`transaction simulation failed: ${body.error?.message ?? response.statusText}`);
  }
  if (!body.result) {
    throw new Error('transaction simulation failed: missing RPC result');
  }
  if (body.result.error) {
    throw new Error(`transaction simulation failed: ${body.result.error}`);
  }
  const latestLedger = Number(body.result.latestLedger);
  if (!Number.isFinite(latestLedger)) {
    throw new Error('transaction simulation failed: missing latest ledger');
  }
  return {
    latestLedger,
    auth: (body.result.results?.[0]?.auth ?? []).map((entry) =>
      xdr.SorobanAuthorizationEntry.fromXDR(entry, 'base64')),
  };
}

async function waitForTransaction(server: rpc.Server, hash: string): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    const result = await server.getTransaction(hash);
    const status = String(result.status);
    if (status === 'SUCCESS') {
      return;
    }
    if (status === 'FAILED') {
      throw new Error(`transaction failed: ${hash}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`transaction did not confirm in time: ${hash}`);
}

export function planKytSubmit(registerFirst: boolean, helperAvailable = false): AtomicKytSubmitPlan {
  if (registerFirst) {
    if (helperAvailable) {
      return {
        atomic: true,
        operations: ['helper.submit_with_passage'],
      };
    }
    return {
      atomic: false,
      operations: ['register_passage', 'pool.transact'],
    };
  }
  return {
    atomic: true,
    operations: ['pool.transact'],
  };
}

export async function registerKytPassage(params: RegisterPassageParams): Promise<string> {
  const derivation = derivePassageFromTransactContext({
    owner: params.owner,
    nonce: params.nonce,
    publicSignalsBytes: params.publicSignalsBytes,
    ciphertextBytes: params.ciphertextBytes,
    publicLegContext: params.publicLegContext,
  });
  await submitTransaction({
    source: params.source,
    networkPassphrase: params.networkPassphrase,
    rpcUrl: params.rpcUrl,
    fee: '1000000',
    operations: [
      registerPassageOperation(
        params.kytRegistryId,
        derivation.passageId,
        params.expiresAtLedger,
        params.signature,
      ),
    ],
  });
  return derivation.passageId;
}

export async function submitPoolTransact(params: SubmitKytTransactParams): Promise<string> {
  return submitTransaction({
    source: params.source,
    networkPassphrase: params.networkPassphrase,
    rpcUrl: params.rpcUrl,
    fee: '10000000',
    operations: [poolTransactOperation(params)],
  });
}

export async function submitApprovedKytPassage(params: SubmitApprovedKytPassageParams): Promise<string> {
  if (params.source.publicKey() !== params.owner) {
    throw new Error('KYT submit source keypair must match pool transact owner');
  }
  return submitTransaction({
    source: params.source,
    networkPassphrase: params.networkPassphrase,
    rpcUrl: params.rpcUrl,
    fee: '12000000',
    allowNonRootAuth: true,
    operations: [
      helperSubmitWithPassageOperation(
        params.kytSubmitHelperId,
        params,
        params.passageId,
        params.expiresAtLedger,
        params.signature,
      ),
    ],
  });
}

export async function submitWithKytPassage(params: SubmitWithKytPassageParams): Promise<string> {
  const inspect = params.inspectFn
    ?? (async (request: InspectKytPassageRequest) => {
      const { inspectKytPassage } = await import('./kyt-passage.js');
      const approved = await inspectKytPassage('', request);
      return approved;
    });

  const approved = await inspect(params.inspectRequest);
  const derivation = derivePassageFromTransactContext({
    owner: params.owner,
    nonce: params.nonce,
    publicSignalsBytes: params.publicSignalsBytes,
    ciphertextBytes: params.ciphertextBytes,
    publicLegContext: params.publicLegContext,
  });
  if (approved.passageId.replace(/^0x/, '') !== derivation.passageId) {
    throw new Error('KYT approval passageId does not match local transaction context');
  }

  if (params.kytSubmitHelperId) {
    return submitApprovedKytPassage({
      source: params.source,
      networkPassphrase: params.networkPassphrase,
      rpcUrl: params.rpcUrl,
      poolContract: params.poolContract,
      owner: params.owner,
      nonce: params.nonce,
      proofBytes: params.proofBytes,
      publicSignalsBytes: params.publicSignalsBytes,
      kytSubmitHelperId: params.kytSubmitHelperId,
      passageId: derivation.passageId,
      expiresAtLedger: approved.expiresAtLedger,
      signature: approved.signature,
    });
  }

  await submitTransaction({
    source: params.source,
    networkPassphrase: params.networkPassphrase,
    rpcUrl: params.rpcUrl,
    fee: '1000000',
    operations: [
      registerPassageOperation(
        params.kytRegistryId,
        derivation.passageId,
        approved.expiresAtLedger,
        approved.signature,
      ),
    ],
  });
  return submitPoolTransact(params);
}

export function localSignKytPassageAuthorization(
  secretSeed: string,
  authorization: ReturnType<typeof buildKytPassageAuthorization>,
): string {
  const signer = Keypair.fromSecret(secretSeed);
  const sig = signer.sign(Buffer.from(authorization.authorizationHash, 'hex'));
  return sig.toString('base64');
}

export { buildKytPassageAuthorization, derivePassageFromTransactContext, hashPublicSignalBytes };
