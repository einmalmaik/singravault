import {
  deriveAuthRuntimeState,
  type AuthRuntimeState,
  type AuthRuntimeStateInput,
} from './authRuntimeState';

export type VaultSessionEvent =
  | 'auth_init'
  | 'anonymous'
  | 'account_login'
  | 'vault_unlock_start'
  | 'vault_unlock_success'
  | 'vault_lock'
  | 'logout'
  | 'requires_device_key'
  | 'requires_2fa'
  | 'item_quarantine'
  | 'integrity_block'
  | 'error';

export interface VaultSessionMachineInput extends AuthRuntimeStateInput {
  event?: VaultSessionEvent;
}

export function deriveVaultSessionState(input: VaultSessionMachineInput): AuthRuntimeState {
  if (input.event === 'logout') {
    return 'anonymous';
  }
  if (input.event === 'vault_lock' && input.hasUser) {
    return 'vault_locked';
  }

  return deriveAuthRuntimeState(input);
}

export function assertVaultSessionTransitionAllowed(
  from: AuthRuntimeState,
  to: AuthRuntimeState,
): boolean {
  if (from === to) {
    return true;
  }

  if (to === 'anonymous') {
    return true;
  }

  if (from === 'anonymous') {
    return to === 'account_authenticated' || to === 'vault_locked' || to === 'initializing';
  }

  if (from === 'vault_unlocked') {
    return ['vault_locked', 'item_quarantine', 'integrity_blocked', 'error'].includes(to);
  }

  if (from === 'vault_unlocking') {
    return ['vault_unlocked', 'requires_device_key', 'requires_2fa', 'item_quarantine', 'integrity_blocked', 'vault_locked', 'error'].includes(to);
  }

  return true;
}
