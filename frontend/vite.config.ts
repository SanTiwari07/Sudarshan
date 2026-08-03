import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    watch: {
      // Force polling for Windows/WSL2 bind-mount volumes.
      // Without `usePolling: true` AND an explicit `interval`, Vite falls back
      // to inotify events, which fail with EIO when the Docker-mounted /app path
      // becomes momentarily unavailable during rebuilds or container restarts.
      usePolling: true,
      interval: 300,
      binaryInterval: 600,
      // Exclude heavy directories — polling them on every interval wastes CPU
      // and can itself trigger stat errors on stale bind-mount inodes.
      ignored: ['**/node_modules/**', '**/.git/**', '**/dist/**'],
    },
    proxy: {
      '/api': {
        target: 'http://backend:8000',
        changeOrigin: true,
      }
    }
  }
})
