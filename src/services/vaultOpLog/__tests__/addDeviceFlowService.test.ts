// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import { getBrowserDeviceTrustStatus } from '../addDeviceFlowService';

describe('addDeviceFlowService device trust policy', () => {
  it('does not treat a logged-in browser without a local device identity as trusted', () => {
    expect(getBrowserDeviceTrustStatus(['trusted-device-1'], null)).toEqual({
      trusted: false,
      reason: 'no_device_identity',
    });
  });

  it('requires the local device identity to be present in the verified trust list', () => {
    expect(getBrowserDeviceTrustStatus(['trusted-device-1'], {
      deviceId: 'browser-device-1',
      publicSigningKeyB64Url: 'public-key',
    })).toEqual({
      trusted: false,
      reason: 'not_in_trust_list',
    });
  });

  it('marks the local device trusted only when the verified trust list contains it', () => {
    expect(getBrowserDeviceTrustStatus(['trusted-device-1', 'browser-device-1'], {
      deviceId: 'browser-device-1',
      publicSigningKeyB64Url: 'public-key',
    })).toEqual({
      trusted: true,
      deviceId: 'browser-device-1',
    });
  });
});
