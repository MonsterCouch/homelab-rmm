import { lazy, Suspense, type ReactNode } from 'react';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
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
import { Baselines } from './pages/Baselines';
import { BaselineEditor } from './pages/BaselineEditor';
import { BaselineStatus } from './pages/BaselineStatus';
import { Alerts } from './pages/Alerts';
import { Patches } from './pages/Patches';
import { Settings } from './pages/Settings';
import { Users } from './pages/Users';
import { Roles } from './pages/Roles';
import { Organizations } from './pages/Organizations';
import { SoftwareCatalog } from './pages/SoftwareCatalog';
import { Discovery } from './pages/Discovery';
import { Tickets } from './pages/Tickets';
import { TicketDetail } from './pages/TicketDetail';
import { Audit } from './pages/Audit';
import { Account } from './pages/Account';
import { Approvals } from './pages/Approvals';
import { TrustSigning } from './pages/TrustSigning';
import { ClientPortal } from './pages/portal/ClientPortal';

// The device detail pulls in xterm and the desktop viewer; keep it off the
// initial bundle.
const DeviceDetail = lazy(() => import('./pages/device/DeviceDetail').then((m) => ({ default: m.DeviceDetail })));

function Guard({ children }: { children: ReactNode }) {
  const { user, needsSetup } = useAuth();
  const loc = useLocation();
  if (user === undefined) return <FullLoading />;
  if (needsSetup) return <Navigate to="/setup" replace />;
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  // A client contact has the support portal and their own account page
  // (password, two-step sign-in), never the console. The server refuses them
  // everything else anyway; this keeps them from landing on empty pages.
  if (user.base_role === 'poc') {
    return loc.pathname === '/account' ? (
      <div className="content" style={{ maxWidth: 720, margin: '0 auto', padding: 24 }}>
        <p>
          <Link to="/portal/tickets?tab=tickets">← Back to support tickets</Link>
        </p>
        <Account />
      </div>
    ) : (
      <Navigate to="/portal/tickets?tab=tickets" replace />
    );
  }
  return <>{children}</>;
}

function AdminOnly({ children }: { children: ReactNode }) {
  const { isAdmin } = useAuth();
  if (!isAdmin) return <Navigate to="/" replace />;
  return <>{children}</>;
}

function AutomationsOnly({ children }: { children: ReactNode }) {
  const { canAutomations } = useAuth();
  if (!canAutomations) return <Navigate to="/" replace />;
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
      <Route path="/portal/*" element={<ClientPortal />} />
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
        <Route
          path="automations"
          element={
            <AutomationsOnly>
              <Automations />
            </AutomationsOnly>
          }
        />
        <Route path="baselines" element={<Baselines />} />
        {/* static before dynamic: /baselines/new must not be read as an id */}
        <Route path="baselines/new" element={<BaselineEditor />} />
        <Route path="baselines/:id" element={<BaselineStatus />} />
        <Route path="baselines/:id/edit" element={<BaselineEditor />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="patches" element={<Patches />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="software-catalog" element={<SoftwareCatalog />} />
        <Route path="discovery" element={<Discovery />} />
        <Route path="tickets" element={<Tickets />} />
        <Route path="tickets/:id" element={<TicketDetail />} />
        <Route
          path="organizations"
          element={
            <AdminOnly>
              <Organizations />
            </AdminOnly>
          }
        />
        <Route
          path="settings"
          element={
            <AdminOnly>
              <Settings />
            </AdminOnly>
          }
        />
        <Route
          path="trust"
          element={
            <AdminOnly>
              <TrustSigning />
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
        <Route
          path="roles"
          element={
            <AdminOnly>
              <Roles />
            </AdminOnly>
          }
        />
        <Route
          path="audit"
          element={
            <AdminOnly>
              <Audit />
            </AdminOnly>
          }
        />
        <Route path="account" element={<Account />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
