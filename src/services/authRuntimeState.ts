export type AuthRuntimeState =
  | "initializing"
  | "anonymous"
  | "account_authenticated"
  | "vault_locked"
  | "vault_unlocking"
  | "vault_unlocked"
  | "requires_2fa"
  | "requires_device_key"
  | "item_quarantine"
  | "integrity_blocked"
  | "error";

export interface AuthRuntimeStateInput {
  authReady: boolean;
  authLoading: boolean;
  hasUser: boolean;
  vaultLoading: boolean;
  vaultUnlocking?: boolean;
  vaultUnlocked: boolean;
  requiresTwoFactor: boolean;
  requiresDeviceKey: boolean;
  hasItemQuarantine?: boolean;
  integrityBlocked?: boolean;
  hasError: boolean;
}

export function deriveAuthRuntimeState(input: AuthRuntimeStateInput): AuthRuntimeState {
  if (input.hasError) {
    return "error";
  }

  if (!input.authReady || input.authLoading || input.vaultLoading) {
    return "initializing";
  }

  if (!input.hasUser) {
    return "anonymous";
  }

  if (input.integrityBlocked) {
    return "integrity_blocked";
  }

  if (input.requiresDeviceKey) {
    return "requires_device_key";
  }

  if (input.requiresTwoFactor) {
    return "requires_2fa";
  }

  if (input.hasItemQuarantine) {
    return "item_quarantine";
  }

  if (input.vaultUnlocking) {
    return "vault_unlocking";
  }

  if (input.vaultUnlocked) {
    return "vault_unlocked";
  }

  return "vault_locked";
}
