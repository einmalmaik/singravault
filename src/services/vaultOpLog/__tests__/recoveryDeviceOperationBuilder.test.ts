import { describe, expect, it } from 'vitest';

import {
  buildRecoverDeviceOperation,
  buildRecoveryCodesRotateOperation,
  toVaultOperationRowFromSigned,
} from '../vaultOpLogOperationBuilder';
import {
  applyRecoveryCodeRotationOperation,
} from '../recoveryCodeTrustService';
import { generateDeviceSigningKeyPair } from '../operationSigningService';
import { verifyOperation } from '../verifyOperation';
import { DEVICE_SIGNATURE_SCHEMA_V2, type TrustedDeviceRecordV1 } from '../types';

const VAULT_ID = 'vault-recovery-test';
const SET_ID = '11111111-1111-4111-8111-111111111111';
const TRUSTED_DEVICE_ID = '22222222-2222-4222-8222-222222222222';
const RECOVERED_DEVICE_ID = '33333333-3333-4333-8333-333333333333';

describe('vault device recovery operations', () => {
  it('signs recovery code rotation with device-signature-v2 commitments', async () => {
    const trusted = await generateDeviceSigningKeyPair();
    const built = await buildRecoveryCodesRotateOperation({
      opId: crypto.randomUUID(),
      intentId: crypto.randomUUID(),
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: TRUSTED_DEVICE_ID,
      deviceSigningKey: trusted.privateKey,
      trustEpoch: 0,
      baseVaultHead: null,
      recoveryCodeSetId: SET_ID,
      recoveryCodeCommitments: ['commitment-a', 'commitment-b'],
    });

    expect(built.signedOperation.body.signatureSchema).toBe(DEVICE_SIGNATURE_SCHEMA_V2);
    expect(built.signedOperation.body.opType).toBe('recovery_codes_rotate');
    expect(built.signedOperation.body.recordType).toBe('manifest');
    expect(built.signedOperation.body.recoveryCodeSetId).toBe(SET_ID);
    expect(built.signedOperation.body.recoveryCodeCommitments).toEqual(['commitment-a', 'commitment-b']);
  });

  it('verifies recover_device only against an active signed recovery-code set', async () => {
    const trusted = await generateDeviceSigningKeyPair();
    const recovered = await generateDeviceSigningKeyPair();
    const trust = {
      vaultId: VAULT_ID,
      trustedDevicesById: new Map<string, TrustedDeviceRecordV1>([[
        TRUSTED_DEVICE_ID,
        {
          vaultId: VAULT_ID,
          deviceId: TRUSTED_DEVICE_ID,
          publicSigningKey: trusted.publicKeyB64Url,
          deviceNameEncrypted: '',
          addedByDeviceId: null,
          addedAt: '2026-05-11T10:00:00.000Z',
          trustEpoch: 0,
          status: 'trusted',
          revokedAt: null,
          revokedByDeviceId: null,
        },
      ]]),
    };

    const rotate = await buildRecoveryCodesRotateOperation({
      opId: crypto.randomUUID(),
      intentId: crypto.randomUUID(),
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: TRUSTED_DEVICE_ID,
      deviceSigningKey: trusted.privateKey,
      trustEpoch: 0,
      baseVaultHead: null,
      recoveryCodeSetId: SET_ID,
      recoveryCodeCommitments: ['commitment-a'],
    });
    const rotateResult = await verifyOperation({
      operation: toVaultOperationRowFromSigned(rotate.signedOperation, rotate.resultingVaultHead),
      trust,
    });
    expect(rotateResult.kind).toBe('validTrustedOperation');
    if (rotateResult.kind !== 'validTrustedOperation') {
      throw new Error('rotation should verify');
    }

    const recoverySets = applyRecoveryCodeRotationOperation(new Map(), rotateResult.signedOperation);
    const recover = await buildRecoverDeviceOperation({
      opId: crypto.randomUUID(),
      intentId: crypto.randomUUID(),
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: RECOVERED_DEVICE_ID,
      deviceSigningKey: recovered.privateKey,
      baseVaultHead: rotate.resultingVaultHead,
      targetPublicSigningKey: recovered.publicKeyB64Url,
      recoveryCodeSetId: SET_ID,
      recoveryCodeCommitment: 'commitment-a',
    });

    const result = await verifyOperation({
      operation: toVaultOperationRowFromSigned(recover.signedOperation, recover.resultingVaultHead),
      trust,
      recoveryTrust: {
        vaultId: VAULT_ID,
        recoveryCodeSetsById: recoverySets,
      },
    });

    expect(result.kind).toBe('validTrustedOperation');
  });

  it('rejects recover_device when the commitment is not in the active set', async () => {
    const trusted = await generateDeviceSigningKeyPair();
    const recovered = await generateDeviceSigningKeyPair();
    const trust = {
      vaultId: VAULT_ID,
      trustedDevicesById: new Map<string, TrustedDeviceRecordV1>([[
        TRUSTED_DEVICE_ID,
        {
          vaultId: VAULT_ID,
          deviceId: TRUSTED_DEVICE_ID,
          publicSigningKey: trusted.publicKeyB64Url,
          deviceNameEncrypted: '',
          addedByDeviceId: null,
          addedAt: '2026-05-11T10:00:00.000Z',
          trustEpoch: 0,
          status: 'trusted',
          revokedAt: null,
          revokedByDeviceId: null,
        },
      ]]),
    };
    const rotate = await buildRecoveryCodesRotateOperation({
      opId: crypto.randomUUID(),
      intentId: crypto.randomUUID(),
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: TRUSTED_DEVICE_ID,
      deviceSigningKey: trusted.privateKey,
      trustEpoch: 0,
      baseVaultHead: null,
      recoveryCodeSetId: SET_ID,
      recoveryCodeCommitments: ['commitment-a'],
    });
    const rotateResult = await verifyOperation({
      operation: toVaultOperationRowFromSigned(rotate.signedOperation, rotate.resultingVaultHead),
      trust,
    });
    if (rotateResult.kind !== 'validTrustedOperation') {
      throw new Error('rotation should verify');
    }
    const recoverySets = applyRecoveryCodeRotationOperation(new Map(), rotateResult.signedOperation);
    const recover = await buildRecoverDeviceOperation({
      opId: crypto.randomUUID(),
      intentId: crypto.randomUUID(),
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: RECOVERED_DEVICE_ID,
      deviceSigningKey: recovered.privateKey,
      baseVaultHead: rotate.resultingVaultHead,
      targetPublicSigningKey: recovered.publicKeyB64Url,
      recoveryCodeSetId: SET_ID,
      recoveryCodeCommitment: 'commitment-b',
    });

    const result = await verifyOperation({
      operation: toVaultOperationRowFromSigned(recover.signedOperation, recover.resultingVaultHead),
      trust,
      recoveryTrust: {
        vaultId: VAULT_ID,
        recoveryCodeSetsById: recoverySets,
      },
    });

    expect(result.kind).toBe('unknownAuthor');
  });
});
