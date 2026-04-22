import { useEffect, useState } from 'react';

import { useAuth } from '@/contexts/AuthContext';
import { getServiceHooks } from '@/extensions/registry';

interface AdminPanelAccessState {
  isAdminUser: boolean;
  showAdminButton: boolean;
}

interface UseAdminPanelAccessOptions {
  enabled?: boolean;
}

export function useAdminPanelAccess(options?: UseAdminPanelAccessOptions): AdminPanelAccessState {
  const { user, session, authReady, authMode, isOfflineSession } = useAuth();
  const [state, setState] = useState<AdminPanelAccessState>({
    isAdminUser: false,
    showAdminButton: false,
  });
  const enabled = options?.enabled ?? true;

  useEffect(() => {
    let isCancelled = false;

    const loadAccess = async () => {
      if (!enabled || !authReady || !user || isOfflineSession || !session?.access_token) {
        console.info('[AdminAccess] Skipping admin access lookup.', {
          enabled,
          authReady,
          authMode,
          hasUser: Boolean(user),
          isOfflineSession,
          hasAccessToken: Boolean(session?.access_token),
        });
        if (!isCancelled) {
          setState({ isAdminUser: false, showAdminButton: false });
        }
        return;
      }

      const hooks = getServiceHooks();
      if (!hooks.getTeamAccess) {
        console.warn('[AdminAccess] Premium admin hook getTeamAccess is not registered.');
        if (!isCancelled) {
          setState({ isAdminUser: false, showAdminButton: false });
        }
        return;
      }

      console.info('[AdminAccess] Loading admin access from premium service.', {
        authMode,
        userId: user.id,
      });
      const { access, error } = await hooks.getTeamAccess();
      if (isCancelled || error || !access) {
        console.warn('[AdminAccess] Admin access lookup failed.', {
          error: error?.message ?? null,
          hasAccess: Boolean(access),
        });
        if (!isCancelled) {
          setState({ isAdminUser: false, showAdminButton: false });
        }
        return;
      }

      console.info('[AdminAccess] Admin access lookup succeeded.', {
        isAdminUser: access.is_admin,
        canAccessAdmin: access.can_access_admin,
      });
      setState({
        isAdminUser: access.is_admin,
        showAdminButton: access.can_access_admin,
      });
    };

    void loadAccess();

    return () => {
      isCancelled = true;
    };
  }, [authMode, authReady, enabled, isOfflineSession, session?.access_token, user]);

  return state;
}
