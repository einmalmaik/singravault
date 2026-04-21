import { useEffect, useState } from 'react';

import { useAuth } from '@/contexts/AuthContext';
import { getServiceHooks } from '@/extensions/registry';

interface AdminPanelAccessState {
  isAdminUser: boolean;
  showAdminButton: boolean;
}

export function useAdminPanelAccess(): AdminPanelAccessState {
  const { user, authReady } = useAuth();
  const [state, setState] = useState<AdminPanelAccessState>({
    isAdminUser: false,
    showAdminButton: false,
  });

  useEffect(() => {
    let isCancelled = false;

    const loadAccess = async () => {
      if (!authReady || !user) {
        if (!isCancelled) {
          setState({ isAdminUser: false, showAdminButton: false });
        }
        return;
      }

      const hooks = getServiceHooks();
      if (!hooks.getTeamAccess) {
        if (!isCancelled) {
          setState({ isAdminUser: false, showAdminButton: false });
        }
        return;
      }

      const { access, error } = await hooks.getTeamAccess();
      if (isCancelled || error || !access) {
        if (!isCancelled) {
          setState({ isAdminUser: false, showAdminButton: false });
        }
        return;
      }

      setState({
        isAdminUser: access.is_admin,
        showAdminButton: access.can_access_admin,
      });
    };

    void loadAccess();

    return () => {
      isCancelled = true;
    };
  }, [authReady, user]);

  return state;
}
