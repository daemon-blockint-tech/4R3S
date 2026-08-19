import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const API_TARGET = process.env.ARES_API_URL || 'http://127.0.0.1:3333'

export default defineConfig({
  base: '/ui/',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
    // @ares/ui is a local file: link (packages/ui) with its own, separate
    // react/react-dom installed as peer deps — without this, Vite's dev
    // server loads two distinct React instances (one from this app, one
    // from packages/ui's own node_modules), and any hook called from a
    // component inside @ares/ui crashes with "Cannot read properties of
    // null (reading 'useRef')" — the classic invalid-hook-call signature
    // for exactly this class of duplicate-React bug. Confirmed directly:
    // packages/ui/node_modules/react exists as a separate copy. This
    // forces every react/react-dom resolution to the single instance in
    // this app's own node_modules, regardless of where the import
    // originates. Production `vite build` didn't hit this — dev and
    // build resolve modules differently, which is exactly why this only
    // surfaced once someone actually ran the dev server.
    dedupe: ['react', 'react-dom'],
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
  },
})
