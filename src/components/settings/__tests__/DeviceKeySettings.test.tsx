import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';

import { DeviceKeySettings } from '../DeviceKeySettings';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

const mockToast = vi.fn();
vi.mock('@/hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'user-1', email: 'test@example.com' },
  }),
}));

const mockDisableDeviceKey = vi.fn(async () => ({ error: null }));
const mockRefreshDeviceKeyState = vi.fn(async () => undefined);
const mockVaultContext = {
  deviceKeyActive: true,
  enableDeviceKey: vi.fn(),
  disableDeviceKey: mockDisableDeviceKey,
  isLocked: false,
  refreshDeviceKeyState: mockRefreshDeviceKeyState,
  vaultProtectionMode: 'device_key_required',
};
vi.mock('@/contexts/VaultContext', () => ({
  useVault: () => mockVaultContext,
}));

vi.mock('@/integrations/supabase/client', () => ({
  supabase: {
    from: vi.fn(() => ({
      update: vi.fn(() => ({
        eq: vi.fn(async () => ({ error: null })),
      })),
    })),
  },
}));

vi.mock('@/platform/runtime', () => ({
  isTauriRuntime: () => false,
}));

vi.mock('@/services/exportFileService', () => ({
  saveExportFile: vi.fn(async () => undefined),
}));

vi.mock('@/services/deviceKeyService', () => ({
  DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH: 20,
  exportDeviceKeyForTransfer: vi.fn(),
  generateDeviceKeyTransferSecret: vi.fn(() => 'transfer-secret-with-20-chars'),
  importDeviceKeyFromTransfer: vi.fn(),
}));

vi.mock('@/services/deviceKeyDeactivationPolicy', () => ({
  DEVICE_KEY_DEACTIVATION_CONFIRMATION_WORD: 'DISABLE DEVICE KEY',
}));

const mockLoadRemoteVaultProfile = vi.fn(async () => ({
  credentials: {
    vaultProtectionMode: 'device_key_required',
  },
}));
vi.mock('@/services/offlineVaultRuntimeService', () => ({
  loadRemoteVaultProfile: (...args: unknown[]) => mockLoadRemoteVaultProfile(...args),
}));

const mockGetTwoFactorRequirement = vi.fn();
vi.mock('@/services/twoFactorService', () => ({
  getTwoFactorRequirement: (...args: unknown[]) => mockGetTwoFactorRequirement(...args),
}));

describe('DeviceKeySettings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockVaultContext.deviceKeyActive = true;
    mockVaultContext.isLocked = false;
    mockVaultContext.vaultProtectionMode = 'device_key_required';
    mockLoadRemoteVaultProfile.mockResolvedValue({
      credentials: {
        vaultProtectionMode: 'device_key_required',
      },
    });
    mockGetTwoFactorRequirement.mockResolvedValue({
      context: 'vault_unlock',
      required: false,
      status: 'loaded',
    });
  });

  it('does not show the authenticator-code field when vault 2FA is disabled', async () => {
    render(<DeviceKeySettings />);

    fireEvent.click(screen.getByRole('button', { name: 'deviceKey.disable' }));

    const dialog = await screen.findByRole('dialog');
    await waitFor(() => {
      expect(mockGetTwoFactorRequirement).toHaveBeenCalledWith({
        userId: 'user-1',
        context: 'vault_unlock',
      });
    });

    expect(within(dialog).queryByText('deviceKey.disableTwoFactorCode')).not.toBeInTheDocument();
    expect(within(dialog).getByText('auth.unlock.password')).toBeInTheDocument();
    expect(within(dialog).getByText('deviceKey.disableConfirmLabel')).toBeInTheDocument();
  });

  it('shows the authenticator-code field when vault 2FA is active', async () => {
    mockGetTwoFactorRequirement.mockResolvedValue({
      context: 'vault_unlock',
      required: true,
      status: 'loaded',
      reason: 'vault_2fa_enabled',
    });

    render(<DeviceKeySettings />);

    fireEvent.click(screen.getByRole('button', { name: 'deviceKey.disable' }));

    const dialog = await screen.findByRole('dialog');
    await waitFor(() => {
      expect(within(dialog).getByText('deviceKey.disableTwoFactorCode')).toBeInTheDocument();
    });
  });

  it('passes the security word to the deactivation service and omits TOTP when vault 2FA is disabled', async () => {
    const { container } = render(<DeviceKeySettings />);

    fireEvent.click(screen.getByRole('button', { name: 'deviceKey.disable' }));
    const dialog = await screen.findByRole('dialog');

    await waitFor(() => {
      expect(within(dialog).queryByText('deviceKey.disableTwoFactorChecking')).not.toBeInTheDocument();
    });

    const inputs = Array.from(dialog.querySelectorAll('input'));
    fireEvent.input(inputs.find((input) => input.type === 'password')!, { target: { value: 'master-password' } });
    fireEvent.input(inputs.find((input) => input.placeholder === 'DISABLE DEVICE KEY')!, {
      target: { value: 'DISABLE DEVICE KEY' },
    });
    fireEvent.click(within(dialog).getByRole('checkbox'));
    const submit = within(dialog).getByRole('button', { name: 'deviceKey.disable' });
    await waitFor(() => {
      expect(submit).not.toBeDisabled();
    });
    fireEvent.click(submit);

    await waitFor(() => {
      expect(mockDisableDeviceKey).toHaveBeenCalledWith(
        'master-password',
        undefined,
        'DISABLE DEVICE KEY',
      );
    });
  });

  it('does not offer export when the global Device Key policy is disabled even if a stale local key exists', () => {
    mockVaultContext.deviceKeyActive = true;
    mockVaultContext.vaultProtectionMode = 'master_only';

    render(<DeviceKeySettings />);

    expect(screen.getByText('deviceKey.inactive')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'deviceKey.export' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'deviceKey.import' })).not.toBeInTheDocument();
  });

  it('offers import but not export when the global policy is active and this device lacks the key', () => {
    mockVaultContext.deviceKeyActive = false;
    mockVaultContext.vaultProtectionMode = 'device_key_required';

    render(<DeviceKeySettings />);

    expect(screen.getByText('deviceKey.importRequired')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'deviceKey.import' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'deviceKey.export' })).not.toBeInTheDocument();
  });
});
