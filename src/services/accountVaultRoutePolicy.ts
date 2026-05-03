export type AccountVaultRouteRequirement =
  | 'anonymous_allowed'
  | 'account_session_required'
  | 'vault_unlock_required';

export type AccountVaultOperation =
  | 'account_settings'
  | 'passkey_management'
  | 'vault_view'
  | 'vault_settings'
  | 'device_key_status'
  | 'device_key_import'
  | 'device_key_export'
  | 'device_key_enable'
  | 'device_key_disable'
  | 'device_key_rewrap'
  | 'quarantine_recovery';

export function getAccountVaultRouteRequirement(
  operation: AccountVaultOperation,
): AccountVaultRouteRequirement {
  switch (operation) {
    case 'account_settings':
    case 'passkey_management':
    case 'device_key_status':
    case 'device_key_import':
      return 'account_session_required';
    case 'vault_view':
    case 'vault_settings':
    case 'device_key_export':
    case 'device_key_enable':
    case 'device_key_disable':
    case 'device_key_rewrap':
    case 'quarantine_recovery':
      return 'vault_unlock_required';
    default:
      return 'anonymous_allowed';
  }
}

export function canAccessAccountVaultOperation(
  operation: AccountVaultOperation,
  state: { hasAccountSession: boolean; isVaultUnlocked: boolean },
): boolean {
  const requirement = getAccountVaultRouteRequirement(operation);
  if (requirement === 'anonymous_allowed') {
    return true;
  }
  if (requirement === 'account_session_required') {
    return state.hasAccountSession;
  }
  return state.hasAccountSession && state.isVaultUnlocked;
}
