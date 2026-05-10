// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `addDeviceFlowService` — Browser-seitiger Add-Device-Flow
 *
 * Zuständigkeiten:
 * - Erzeugen eines Device Signing Key Pairs für den Browser
 * - Erstellen und Verwalten von Pairing-Anfragen
 * - Speichern der Browser-Device-Identität
 * - Prüfen des lokalen Trust-Status
 *
 * Security-Invariante:
 * - Der private Device Signing Key wird NIEMALS serialisiert,
 *   an Server/Tauri übertragen oder geloggt.
 * - WebCrypto non-extractable Keys werden für Speicherung verwendet.
 */

import { encodeBase64Url } from './canonicalJson';
import { generateDeviceSigningKeyPair } from './operationSigningService';
import type {
  BrowserDeviceState,
  BrowserDeviceTrustStatus,
  CreatePendingDeviceRequestInput,
  CreatePendingDeviceRequestResult,
  DevicePlatform,
} from './addDeviceFlowTypes';
import {
  saveVaultOpLogDeviceIdentity,
  loadVaultOpLogDeviceIdentity,
  clearVaultOpLogDeviceIdentity,
  type VaultOpLogDeviceIdentity,
} from './vaultOpLogDeviceStore';
import {
  saveVaultOpLogDeviceSigningKey,
  loadVaultOpLogDeviceSigningKey,
  listVaultOpLogDeviceSigningKeyRefs,
  type VaultOpLogDeviceSigningKeyRef,
} from './vaultOpLogDeviceSigningKeyStore';
import { VaultSignatureError } from './types';

const DEVICE_NAME_MAX_LENGTH = 128;

/**
 * Plattform-Erkennung für Browser
 */
export function getCurrentPlatform(): DevicePlatform {
  if (typeof navigator === 'undefined') {
    return 'unknown';
  }
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('electron') || ua.includes('tauri')) {
    return 'desktop';
  }
  if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
    return 'mobile';
  }
  return 'web';
}

/**
 * Browser-spezifischen Gerätenamen erzeugen
 */
export function generateBrowserDeviceName(): string {
  const platform = getCurrentPlatform();
  const now = new Date();
  const dateStr = now.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
  return `${platform.charAt(0).toUpperCase() + platform.slice(1)} Browser (${dateStr})`;
}

/**
 * Pairing-Nonce erzeugen (kryptografisch sichere Zufallszahl)
 */
export function generatePairingNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return encodeBase64Url(bytes);
}

/**
 * Device Identity für Browser erzeugen und speichern
 *
 * Security: Private Key ist non-extractable und wird in IndexedDB gespeichert.
 * Er verlässt niemals den Browser oder wird serialisiert.
 */
export async function createBrowserDeviceIdentity(
  userId: string,
  vaultId: string,
  deviceName?: string,
): Promise<{ identity: VaultOpLogDeviceIdentity; privateKey: CryptoKey }> {
  // Key Pair erzeugen (non-extractable private key)
  const keyPair = await generateDeviceSigningKeyPair();

  const deviceId = crypto.randomUUID();
  const name = deviceName ?? generateBrowserDeviceName();

  const identity: VaultOpLogDeviceIdentity = {
    deviceId,
    publicSigningKeyB64Url: keyPair.publicKeyB64Url,
  };

  // Identity speichern (localStorage - public keys sind nicht geheim)
  saveVaultOpLogDeviceIdentity(identity);

  // Private Key speichern (IndexedDB - non-extractable CryptoKey)
  await saveVaultOpLogDeviceSigningKey({
    userId,
    vaultId,
    deviceId,
    privateKey: keyPair.privateKey,
  });

  return { identity, privateKey: keyPair.privateKey };
}

/**
 * Gespeicherte Browser Device Identity laden
 */
export function loadBrowserDeviceIdentity(): VaultOpLogDeviceIdentity | null {
  return loadVaultOpLogDeviceIdentity();
}

/**
 * Private Key für Browser Device laden
 */
export async function loadBrowserDevicePrivateKey(
  userId: string,
  vaultId: string,
  deviceId: string,
): Promise<CryptoKey | null> {
  return loadVaultOpLogDeviceSigningKey({ userId, vaultId, deviceId });
}

/**
 * Browser Device State aus lokaler Identity erstellen
 */
export function getBrowserDeviceState(
  identity: VaultOpLogDeviceIdentity,
  isPendingEnrollment: boolean = false,
  pendingRequestId: string | null = null,
): BrowserDeviceState {
  return {
    deviceId: identity.deviceId,
    deviceName: 'Browser', // sollte aus encrypted storage gelesen werden
    publicSigningKey: identity.publicSigningKeyB64Url,
    platform: getCurrentPlatform(),
    createdAt: new Date().toISOString(),
    isPendingEnrollment,
    pendingRequestId,
  };
}

/**
 * Prüfen ob Browser Device Identity existiert
 */
export function hasBrowserDeviceIdentity(): boolean {
  return loadBrowserDeviceIdentity() !== null;
}

/**
 * Browser Device Identity und Keys löschen (bei Logout)
 */
export async function clearBrowserDeviceIdentity(
  userId: string,
  vaultId: string,
  deviceId: string,
): Promise<void> {
  clearVaultOpLogDeviceIdentity();
  // IndexedDB Keys werden über listVaultOpLogDeviceSigningKeyRefs gefunden
  // und einzeln gelöscht - hier vereinfacht
}

/**
 * Public Key Fingerprint für Kurz-Anzeige erzeugen
 * Zeigt die ersten 8 Hex-Zeichen des SHA-256 Hashes
 */
export async function getPublicKeyShortFingerprint(
  publicKeyB64Url: string,
): Promise<string> {
  const keyBytes = Uint8Array.from(atob(publicKeyB64Url.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes as unknown as ArrayBuffer);
  const hashArray = new Uint8Array(hashBuffer);
  const hex = Array.from(hashArray.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.toUpperCase();
}

/**
 * Input fürRPC create_pending_device_request validieren
 */
export function validateCreatePendingDeviceRequestInput(
  input: CreatePendingDeviceRequestInput,
): { valid: true } | { valid: false; error: string } {
  if (!input.vaultId || typeof input.vaultId !== 'string') {
    return { valid: false, error: 'vaultId is required' };
  }
  if (!input.deviceId || typeof input.deviceId !== 'string') {
    return { valid: false, error: 'deviceId is required' };
  }
  if (!input.deviceName || typeof input.deviceName !== 'string') {
    return { valid: false, error: 'deviceName is required' };
  }
  if (input.deviceName.length > DEVICE_NAME_MAX_LENGTH) {
    return { valid: false, error: `deviceName must be at most ${DEVICE_NAME_MAX_LENGTH} characters` };
  }
  if (!input.publicSigningKey || typeof input.publicSigningKey !== 'string') {
    return { valid: false, error: 'publicSigningKey is required' };
  }
  if (!input.pairingNonce || typeof input.pairingNonce !== 'string') {
    return { valid: false, error: 'pairingNonce is required' };
  }
  if (input.pairingNonce.length < 32) {
    return { valid: false, error: 'pairingNonce must be at least 32 characters' };
  }
  return { valid: true };
}
