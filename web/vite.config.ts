import { mkdirSync, writeFileSync } from 'node:fs';
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

// The Go server embeds web/dist (web/embed.go); the dev server proxies API and
// WebSocket traffic to a locally running rmm-server so cookies stay same-origin.
const target = process.env.RMM_DEV_TARGET || 'https://localhost:8443';

// dist/ is emptied on every build so stale hashed chunks do not pile up, but
// `go:embed all:dist` needs the directory tracked in git: put .gitkeep back.
const keepGitkeep = (): Plugin => ({
  name: 'rmm-gitkeep',
  closeBundle() {
    mkdirSync('dist', { recursive: true });
    writeFileSync('dist/.gitkeep', '');
  },
});

export default defineConfig({
  plugins: [react(), keepGitkeep()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          xterm: ['@xterm/xterm', '@xterm/addon-fit'],
          charts: ['uplot'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target, changeOrigin: true, secure: false },
      '/ws': { target, changeOrigin: true, secure: false, ws: true },
    },
  },
});
