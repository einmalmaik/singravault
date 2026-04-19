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

export default function Index() {
  if (isTauriRuntime()) {
    return <Navigate to="/auth" replace />;
  }
  
  return <Landing />;
}
