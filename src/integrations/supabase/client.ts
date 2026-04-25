// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
// Hand-maintained Supabase client bootstrap for Singra Vault.
// Database types remain generated in ./types, but auth/runtime wiring lives here.
import { createClient } from '@supabase/supabase-js';
import type { LockFunc } from '@supabase/auth-js';
import type { Database } from './types';
import { runtimeConfig } from '@/config/runtimeConfig';
import { isTauriRuntime } from '@/platform/runtime';
import { createAuthStorage } from './authStorage';

const SUPABASE_URL = runtimeConfig.supabaseUrl;
const SUPABASE_PUBLISHABLE_KEY = runtimeConfig.supabasePublishableKey;

// Import the supabase client like this:
// import { supabase } from "@/integrations/supabase/client";

const authStorage = createAuthStorage();

// Auth state is scoped to one WebView. A cross-tab Web Lock is unnecessary here
// and can abort OAuth callbacks in Tauri.
const inMemoryAuthLock: LockFunc = async (_name, _acquireTimeout, fn) => await fn();
const isDesktopRuntime = isTauriRuntime();
const authFlowType = isDesktopRuntime ? 'pkce' : 'implicit';

export const supabase = createClient<Database>(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: {
    storage: authStorage,
    persistSession: true,
    autoRefreshToken: false,
    detectSessionInUrl: false,
    flowType: authFlowType,
    lock: inMemoryAuthLock,
  }
});
