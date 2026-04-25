// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for Post-Quantum key-wrapping service
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
    generatePQKeyPair,
    generateHybridKeyPair,
    hybridEncrypt,
    hybridDecrypt,
    hybridWrapKey,
    hybridUnwrapKey,
    isHybridEncrypted,
    isCurrentStandardEncrypted,
    migrateToHybrid,
    SECURITY_STANDARD_VERSION,
    HYBRID_VERSION,
} from './pqCryptoService';

describe('pqCryptoService', () => {
    describe('generatePQKeyPair', () => {
        it('should generate valid ML-KEM-768 key pair', () => {
            const keys = generatePQKeyPair();
            
            expect(keys.publicKey).toBeDefined();
            expect(keys.secretKey).toBeDefined();
            
            // ML-KEM-768 public key is 1184 bytes
            const pubKeyBytes = atob(keys.publicKey);
            expect(pubKeyBytes.length).toBe(1184);
            
            // ML-KEM-768 secret key is 2400 bytes
            const secKeyBytes = atob(keys.secretKey);
            expect(secKeyBytes.length).toBe(2400);
        });

        it('should generate different keys each time', () => {
            const keys1 = generatePQKeyPair();
            const keys2 = generatePQKeyPair();
            
            expect(keys1.publicKey).not.toBe(keys2.publicKey);
            expect(keys1.secretKey).not.toBe(keys2.secretKey);
        });
    });

    describe('generateHybridKeyPair', () => {
        it('should generate valid hybrid key pair', async () => {
            const keys = await generateHybridKeyPair();
            
            expect(keys.pqPublicKey).toBeDefined();
            expect(keys.pqSecretKey).toBeDefined();
            expect(keys.rsaPublicKey).toBeDefined();
            expect(keys.rsaPrivateKey).toBeDefined();
            
            // RSA keys should be valid JWK
            const rsaPubJwk = JSON.parse(keys.rsaPublicKey);
            expect(rsaPubJwk.kty).toBe('RSA');
            expect(rsaPubJwk.alg).toBe('RSA-OAEP-256');
            
            const rsaPrivJwk = JSON.parse(keys.rsaPrivateKey);
            expect(rsaPrivJwk.kty).toBe('RSA');
            expect(rsaPrivJwk.d).toBeDefined(); // Private exponent
        });
    });

    describe('hybridEncrypt / hybridDecrypt', () => {
        let hybridKeys: Awaited<ReturnType<typeof generateHybridKeyPair>>;
        
        beforeAll(async () => {
            hybridKeys = await generateHybridKeyPair();
        });

        it('should encrypt and decrypt short text', async () => {
            const plaintext = 'Serialized sharing key material';
            
            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            expect(ciphertext).toBeDefined();
            expect(ciphertext).not.toBe(plaintext);
            
            const decrypted = await hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
            );
            
            expect(decrypted).toBe(plaintext);
        });

        it('should encrypt and decrypt long text', async () => {
            const plaintext = 'A'.repeat(10000);
            
            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            const decrypted = await hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
            );
            
            expect(decrypted).toBe(plaintext);
        });

        it('should encrypt and decrypt JSON data', async () => {
            const data = {
                username: 'test@example.com',
                password: 'super-secret-password-123!',
                notes: 'Some important notes with special chars: äöü€',
            };
            const plaintext = JSON.stringify(data);
            
            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            const decrypted = await hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
            );
            
            expect(JSON.parse(decrypted)).toEqual(data);
        });

        it('should produce different ciphertext for same plaintext', async () => {
            const plaintext = 'Same message';
            
            const ciphertext1 = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            const ciphertext2 = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            expect(ciphertext1).not.toBe(ciphertext2);
            
            // Both should decrypt to same plaintext
            const decrypted1 = await hybridDecrypt(
                ciphertext1,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
            );
            const decrypted2 = await hybridDecrypt(
                ciphertext2,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
            );
            
            expect(decrypted1).toBe(plaintext);
            expect(decrypted2).toBe(plaintext);
        });

        it('should fail with wrong PQ secret key', async () => {
            const plaintext = 'Secret message';
            const wrongKeys = generatePQKeyPair();
            
            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            await expect(hybridDecrypt(
                ciphertext,
                wrongKeys.secretKey, // Wrong PQ key
                hybridKeys.rsaPrivateKey
            )).rejects.toThrow();
        });

        it('should fail with wrong RSA private key', async () => {
            const plaintext = 'Secret message';
            const wrongKeys = await generateHybridKeyPair();
            
            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            await expect(hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                wrongKeys.rsaPrivateKey // Wrong RSA key
            )).rejects.toThrow();
        });

        it('should block legacy hybrid ciphertext versions in runtime decrypt path', async () => {
            const legacyHybrid = btoa(String.fromCharCode(0x02) + 'legacy');

            await expect(hybridDecrypt(
                legacyHybrid,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
            )).rejects.toThrow('Security Standard v1 requires hybrid ciphertext version 3 or 4.');
        });
    });

    describe('hybridEncrypt / hybridDecrypt with AAD', () => {
        let hybridKeys: Awaited<ReturnType<typeof generateHybridKeyPair>>;

        beforeAll(async () => {
            hybridKeys = await generateHybridKeyPair();
        });

        it('should encrypt and decrypt with AAD', async () => {
            const plaintext = 'AAD-protected data';
            const aad = 'collection-id-12345';

            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey,
                aad
            );

            const decrypted = await hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey,
                aad
            );

            expect(decrypted).toBe(plaintext);
        });

        it('should fail when AAD does not match', async () => {
            const plaintext = 'AAD-protected data';
            const aad = 'collection-id-12345';

            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey,
                aad
            );

            await expect(hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey,
                'wrong-aad'
            )).rejects.toThrow();
        });

        it('should fail when AAD is expected but not provided', async () => {
            const plaintext = 'AAD-protected data';
            const aad = 'collection-id-12345';

            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey,
                aad
            );

            await expect(hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
                // no AAD
            )).rejects.toThrow();
        });

        it('should decrypt without AAD when encrypted without AAD', async () => {
            const plaintext = 'No AAD data';

            const ciphertext = await hybridEncrypt(
                plaintext,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
                // no AAD
            );

            const decrypted = await hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
                // no AAD
            );

            expect(decrypted).toBe(plaintext);
        });
    });

    describe('hybridWrapKey / hybridUnwrapKey', () => {
        it('should wrap and unwrap shared AES key', async () => {
            const hybridKeys = await generateHybridKeyPair();
            
            // Generate a mock shared AES key
            const mockSharedKey = JSON.stringify({
                kty: 'oct',
                k: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                alg: 'A256GCM',
            });
            
            const wrapped = await hybridWrapKey(
                mockSharedKey,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            expect(wrapped).toBeDefined();
            
            const unwrapped = await hybridUnwrapKey(
                wrapped,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey
            );
            
            expect(unwrapped).toBe(mockSharedKey);
        });

        it('should wrap and unwrap with AAD', async () => {
            const hybridKeys = await generateHybridKeyPair();
            const mockSharedKey = JSON.stringify({
                kty: 'oct',
                k: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                alg: 'A256GCM',
            });
            const collectionId = 'col-abc-123';

            const wrapped = await hybridWrapKey(
                mockSharedKey,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey,
                collectionId
            );

            const unwrapped = await hybridUnwrapKey(
                wrapped,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey,
                collectionId
            );

            expect(unwrapped).toBe(mockSharedKey);
        });
    });

    describe('isHybridEncrypted', () => {
        it('should return true for current v4 hybrid wrapped key material', async () => {
            const hybridKeys = await generateHybridKeyPair();
            
            const ciphertext = await hybridEncrypt(
                'test',
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            expect(isHybridEncrypted(ciphertext)).toBe(true);
        });

        it('should return true for legacy v3 hybrid data', () => {
            const v3Data = btoa(String.fromCharCode(0x03) + 'some-v3-ciphertext');
            expect(isHybridEncrypted(v3Data)).toBe(true);
        });

        it('should return true for legacy v2 hybrid data', () => {
            const v2Data = btoa(String.fromCharCode(0x02) + 'some-v2-ciphertext');
            expect(isHybridEncrypted(v2Data)).toBe(true);
        });

        it('should return false for invalid base64', () => {
            expect(isHybridEncrypted('not-valid-base64!!!')).toBe(false);
        });

        it('should return false for legacy RSA-only format', () => {
            // Version byte 0x01 indicates RSA-only
            const legacyData = btoa(String.fromCharCode(0x01) + 'some-rsa-ciphertext');
            expect(isHybridEncrypted(legacyData)).toBe(false);
        });
    });

    describe('isCurrentStandardEncrypted', () => {
        it('should return true for v4 ciphertext', async () => {
            const hybridKeys = await generateHybridKeyPair();

            const ciphertext = await hybridEncrypt(
                'test',
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );

            expect(isCurrentStandardEncrypted(ciphertext)).toBe(true);
        });

        it('should return false for v3 ciphertext', () => {
            const v3Data = btoa(String.fromCharCode(0x03) + 'some-v3-data');
            expect(isCurrentStandardEncrypted(v3Data)).toBe(false);
        });

        it('should return false for v2 ciphertext', () => {
            const v2Data = btoa(String.fromCharCode(0x02) + 'some-v2-data');
            expect(isCurrentStandardEncrypted(v2Data)).toBe(false);
        });

        it('should return false for invalid base64', () => {
            expect(isCurrentStandardEncrypted('not-valid!!!')).toBe(false);
        });
    });

    describe('migrateToHybrid', () => {
        it('should return already-v4 data unchanged', async () => {
            const hybridKeys = await generateHybridKeyPair();
            
            const ciphertext = await hybridEncrypt(
                'test',
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            const migrated = await migrateToHybrid(
                ciphertext,
                hybridKeys.rsaPrivateKey,
                hybridKeys.pqSecretKey,
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );
            
            // Should return same ciphertext since it's already v4
            expect(migrated).toBe(ciphertext);
        });
    });

    describe('hybrid ciphertext parsing', () => {
        it.each([
            ['truncated PQ segment', 1 + 500],
            ['truncated RSA segment', 1 + 1088 + 100],
            ['missing IV', 1 + 1088 + 512],
            ['missing AES-GCM tag', 1 + 1088 + 512 + 12 + 8],
        ])('should reject %s as a generic format error', async (_caseName, byteLength) => {
            const hybridKeys = await generateHybridKeyPair();
            const ciphertext = await hybridEncrypt(
                'test',
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey,
            );
            const raw = atob(ciphertext);
            const truncated = btoa(raw.slice(0, byteLength));

            await expect(hybridDecrypt(
                truncated,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey,
            )).rejects.toThrow('Invalid hybrid ciphertext format.');
        });

        it('should keep valid v4 ciphertext compatible', async () => {
            const hybridKeys = await generateHybridKeyPair();
            const ciphertext = await hybridEncrypt(
                'valid v4 ciphertext',
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey,
            );

            await expect(hybridDecrypt(
                ciphertext,
                hybridKeys.pqSecretKey,
                hybridKeys.rsaPrivateKey,
            )).resolves.toBe('valid v4 ciphertext');
        });
    });

    describe('HYBRID_VERSION constant', () => {
        it('should be version 4', () => {
            expect(HYBRID_VERSION).toBe(4);
        });
    });

    describe('SECURITY_STANDARD_VERSION constant', () => {
        it('should be version 1', () => {
            expect(SECURITY_STANDARD_VERSION).toBe(1);
        });
    });

    describe('version byte in ciphertext', () => {
        it('should produce ciphertext with version 0x04', async () => {
            const hybridKeys = await generateHybridKeyPair();

            const ciphertext = await hybridEncrypt(
                'test',
                hybridKeys.pqPublicKey,
                hybridKeys.rsaPublicKey
            );

            const raw = atob(ciphertext);
            expect(raw.charCodeAt(0)).toBe(0x04);
        });
    });
});
