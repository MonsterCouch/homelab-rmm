import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import '@xterm/xterm/css/xterm.css';
import './styles/global.css';
import { App } from './App';
import { AuthProvider } from './state/auth';
import { ToastProvider } from './state/toast';
import { ConfirmProvider } from './components/Modal';
import { EventsProvider } from './hooks/useEvents';
import { ErrorBoundary } from './components/ui';
import { applyTheme } from './hooks/useTheme';

// Paint the right theme before React mounts so there is no flash.
try {
  const stored = localStorage.getItem('rmm.theme');
  applyTheme(stored === 'light' || stored === 'dark' ? stored : window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
} catch {
  applyTheme('dark');
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <ToastProvider>
        <AuthProvider>
          <EventsProvider>
            <ConfirmProvider>
              <BrowserRouter>
                <App />
              </BrowserRouter>
            </ConfirmProvider>
          </EventsProvider>
        </AuthProvider>
      </ToastProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
