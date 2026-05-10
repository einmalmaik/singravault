// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Add-Device-Flow: Client-seitige Typen und Zustände
 *
 * Dieser Flow ermöglicht es einem neuen Gerät (z.B. Browser),
 * nach dem Login als vertrauenswürdiges Gerät aufgenommen zu werden.
 *
 * Flow:
 *  1. Browser erstellt Pending Request mit eigenem Public Signing Key
 *  2. Tauri zeigt offene Requests und ermöglicht Bestätigung/Ablehnung
 *  3. Bei Bestätigung: Tauri signiert add_device Operation
 *  4. Browser wird nach Sync erst dann trusted
 */

/**
 * Status einer Pairing-Anfrage
 */
export type PendingDeviceRequestStatus = 'pending' | 'approved' | 'rejected' | 'expired';

/**
 * Plattform eines Geräts
 */
export type DevicePlatform = 'web' | 'tauri' | 'mobile' | 'desktop' | 'unknown';

/**
 * Pairing-Anfrage wie vom Server empfangen
 */
export interface PendingDeviceRequestRow {
  readonly requestId: string;
  readonly requestedDeviceId: string;
  readonly requestedDeviceName: string;
  readonly requestedPublicSigningKey: string;
  readonly requestedDevicePlatform: DevicePlatform | null;
  readonly pairingNonce: string;
  readonly challengeCreatedAt: string;
  readonly challengeExpiresAt: string;
  readonly status: PendingDeviceRequestStatus;
  readonly createdAt: string;
}

/**
 * Eingabe für das Erstellen einer Pairing-Anfrage
 */
export interface CreatePendingDeviceRequestInput {
  readonly vaultId: string;
  readonly deviceId: string;
  readonly deviceName: string;
  readonly publicSigningKey: string;
  readonly devicePlatform: DevicePlatform;
  readonly pairingNonce: string;
}

/**
 * Ergebnis des Erstellens einer Pairing-Anfrage
 */
export interface CreatePendingDeviceRequestResult {
  readonly created: boolean;
  readonly requestId: string | null;
  readonly expiresAt: string | null;
  readonly reason?: 'device_already_trusted';
}

/**
 * Ergebnis der Bestätigung einer Pairing-Anfrage
 * Enthält die Daten für die add_device Operation
 */
export interface ApprovePendingDeviceRequestResult {
  readonly approved: boolean;
  readonly requestId?: string;
  readonly requestedDeviceId?: string;
  readonly requestedPublicSigningKey?: string;
  readonly requestedDeviceName?: string;
  readonly vaultId?: string;
  readonly reason?: 'request_not_found' | 'request_expired' | 'approver_not_trusted';
}

/**
 * Ergebnis der Ablehnung einer Pairing-Anfrage
 */
export interface RejectPendingDeviceRequestResult {
  readonly rejected: boolean;
  readonly requestId?: string;
  readonly reason?: 'request_not_found';
}

/**
 * Lokaler Browser Device State
 */
export interface BrowserDeviceState {
  readonly deviceId: string;
  readonly deviceName: string;
  readonly publicSigningKey: string;
  readonly platform: DevicePlatform;
  readonly createdAt: string;
  readonly isPendingEnrollment: boolean;
  readonly pendingRequestId: string | null;
}

/**
 * Resultat der Prüfung ob Browser als trusted Device agieren darf
 */
export type BrowserDeviceTrustStatus =
  | { readonly trusted: true; readonly deviceId: string }
  | { readonly trusted: false; readonly reason: 'no_device_identity' | 'not_in_trust_list' | 'revoked' };

/**
 * Add-Device-Operation Payload für submit_vault_operation
 */
export interface AddDeviceOperationPayload {
  readonly kind: 'add';
  readonly device: {
    readonly vaultId: string;
    readonly deviceId: string;
    readonly publicSigningKey: string;
    readonly deviceNameEncrypted: string;
    readonly addedByDeviceId: string;
    readonly addedAt: string;
    readonly trustEpoch: number;
  };
}

/**
 * Kurzinfo für Pairing-Code Anzeige
 */
export interface PairingCodeInfo {
  readonly shortFingerprint: string;
  readonly deviceName: string;
  readonly platform: DevicePlatform;
  readonly createdAt: string;
}
