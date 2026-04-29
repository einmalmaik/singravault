export type AuthRuntimeState =
  | "initializing"
  | "anonymous"
  | "authenticated_locked"
  | "authenticated_unlocked"
  | "requires_2fa"
  | "requires_device_key"
  | "error";

export interface AuthRuntimeStateInput {
  authReady: boolean;
  authLoading: boolean;
  hasUser: boolean;
  vaultLoading: boolean;
  vaultUnlocked: boolean;
  requiresTwoFactor: boolean;
  requiresDeviceKey: boolean;
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

  if (input.requiresDeviceKey) {
    return "requires_device_key";
  }

  if (input.requiresTwoFactor) {
    return "requires_2fa";
  }

  return input.vaultUnlocked ? "authenticated_unlocked" : "authenticated_locked";
}
