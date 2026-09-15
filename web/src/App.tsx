import { lazy, Suspense, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Loading } from './components/ui';
import { useAuth } from './state/auth';
import { Login } from './pages/Login';
import { Setup } from './pages/Setup';
import { Dashboard } from './pages/Dashboard';
import { Devices } from './pages/Devices';
import { Scripts } from './pages/Scripts';
import { ScriptEditor } from './pages/ScriptEditor';
import { Runs } from './pages/Runs';
import { Tasks } from './pages/Tasks';
import { Automations } from './pages/Automations';
import { Alerts } from './pages/Alerts';
import { Patches } from './pages/Patches';
import { Settings } from './pages/Settings';
import { Users } from './pages/Users';
import { Audit } from './pages/Audit';
import { Account } from './pages/Account';

// The device detail pulls in xterm and the desktop viewer; keep it off the
// initial bundle.
const DeviceDetail = lazy(() => import('./pages/device/DeviceDetail').then((m) => ({ default: m.DeviceDetail })));

function Guard({ children }: { children: ReactNode }) {
  const { user, needsSetup } = useAuth();
  const loc = useLocation();
  if (user === undefined) return <FullLoading />;
  if (needsSetup) return <Navigate to="/setup" replace />;
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  return <>{children}</>;
}

function AdminOnly({ children }: { children: ReactNode }) {
  const { isAdmin } = useAuth();
  if (!isAdmin) return <Navigate to="/" replace />;
  return <>{children}</>;
}

function FullLoading() {
  return (
    <div className="auth">
      <Loading />
    </div>
  );
}

export function App() {
  const { user, needsSetup } = useAuth();
  return (
    <Routes>
      <Route path="/setup" element={user === undefined ? <FullLoading /> : needsSetup ? <Setup /> : <Navigate to="/" replace />} />
      <Route path="/login" element={user === undefined ? <FullLoading /> : needsSetup ? <Navigate to="/setup" replace /> : user ? <Navigate to="/" replace /> : <Login />} />
      <Route
        path="/"
        element={
          <Guard>
            <Layout />
          </Guard>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="devices" element={<Devices />} />
        <Route
          path="devices/:id/:tab?"
          element={
            <Suspense fallback={<Loading />}>
              <DeviceDetail />
            </Suspense>
          }
        />
        <Route path="scripts" element={<Scripts />} />
        <Route path="scripts/new" element={<ScriptEditor />} />
        <Route path="scripts/:id" element={<ScriptEditor />} />
        <Route path="runs" element={<Runs />} />
        <Route path="tasks" element={<Tasks />} />
        <Route path="automations" element={<Automations />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="patches" element={<Patches />} />
        <Route
          path="settings"
          element={
            <AdminOnly>
              <Settings />
            </AdminOnly>
          }
        />
        <Route
          path="users"
          element={
            <AdminOnly>
              <Users />
            </AdminOnly>
          }
        />
        <Route path="audit" element={<Audit />} />
        <Route path="account" element={<Account />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
