import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, setUnauthorizedHandler } from '../api/client';
import type { User } from '../api/types';
import { forgetGrants } from '../lib/grants';

interface AuthCtx {
  /** undefined while the initial /api/auth/state request is in flight */
  user: User | null | undefined;
  needsSetup: boolean;
  setupCodeRequired: boolean;
  version: string;
  refresh: () => Promise<void>;
  setUser: (u: User | null) => void;
  logout: () => Promise<void>;
  canWrite: boolean;
  isAdmin: boolean;
  /** true for admins, else whether the role grants this permission key */
  can: (perm: string) => boolean;
  /** may open the Automations page: admin, or automations.edit with no organization restriction */
  canAutomations: boolean;
  /** may create and delete automations (every automation, not just a scoped few) */
  allAutomations: boolean;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [setupCodeRequired, setSetupCodeRequired] = useState(false);
  const [version, setVersion] = useState('');

  const refresh = useCallback(async () => {
    try {
      const st = await api.authState();
      setNeedsSetup(st.needs_setup);
      setSetupCodeRequired(st.setup_code_required ?? false);
      setVersion(st.version);
      setUser(st.user);
    } catch {
      // The server is unreachable: treat as signed out so the login page
      // renders and shows the network error on submit.
      setUser(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // A 401 anywhere means the session expired (or was revoked by a password
  // reset): drop the user so the route guard sends us to /login.
  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    return () => setUnauthorizedHandler(null);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      // signed grants belong to the operator who signed them
      forgetGrants();
      setUser(null);
    }
  }, []);

  const value = useMemo<AuthCtx>(() => {
    const isAdmin = !!user && user.base_role === 'admin';
    const can = (perm: string) => isAdmin || user?.permissions?.[perm] === true;
    const canAutomations = isAdmin || (can('automations.edit') && !user?.org_scope?.length);
    return {
      user,
      needsSetup,
      setupCodeRequired,
      version,
      refresh,
      setUser,
      logout,
      canWrite: !!user && (user.base_role === 'admin' || user.base_role === 'tech'),
      isAdmin,
      can,
      canAutomations,
      allAutomations: isAdmin || (canAutomations && user?.automation_scope === 'all'),
    };
  }, [user, needsSetup, setupCodeRequired, version, refresh, logout]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error('useAuth outside AuthProvider');
  return v;
}
