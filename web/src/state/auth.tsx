import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, setUnauthorizedHandler } from '../api/client';
import type { User } from '../api/types';

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
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [setupCodeRequired, setSetupCodeRequired] = useState(true);
  const [version, setVersion] = useState('');

  const refresh = useCallback(async () => {
    try {
      const st = await api.authState();
      setNeedsSetup(st.needs_setup);
      setSetupCodeRequired(st.setup_code_required ?? true);
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
      setUser(null);
    }
  }, []);

  const value = useMemo<AuthCtx>(
    () => ({
      user,
      needsSetup,
      setupCodeRequired,
      version,
      refresh,
      setUser,
      logout,
      canWrite: !!user && user.role !== 'viewer',
      isAdmin: !!user && user.role === 'admin',
    }),
    [user, needsSetup, setupCodeRequired, version, refresh, logout],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error('useAuth outside AuthProvider');
  return v;
}
