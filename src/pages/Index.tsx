// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Index Page
 * 
 * Redirects to Landing page for the root route.
 */

import Landing from './Landing';
import { isTauriRuntime } from '@/platform/runtime';
import { Navigate } from 'react-router-dom';
import { hasOAuthCallbackPayload } from '@/platform/tauriOAuthCallback';

export default function Index() {
  if (isTauriRuntime()) {
    const callbackSuffix = `${window.location.search}${window.location.hash}`;
    const target = hasOAuthCallbackPayload(window.location.href, window.location.origin)
      ? `/auth${callbackSuffix}`
      : '/vault';
    return <Navigate to={target} replace />;
  }

  return <Landing />;
}
