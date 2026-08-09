// vite.config.ts
import { defineConfig } from "file:///app/node_modules/vite/dist/node/index.js";
import react from "file:///app/node_modules/@vitejs/plugin-react/dist/index.js";
var vite_config_default = defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
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
      // Exclude heavy directories - polling them on every interval wastes CPU
      // and can itself trigger stat errors on stale bind-mount inodes.
      ignored: ["**/node_modules/**", "**/.git/**", "**/dist/**"]
    },
    proxy: {
      "/api": {
        target: "http://backend:8000",
        changeOrigin: true
      }
    }
  }
});
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ZpbGVuYW1lID0gXCIvYXBwL3ZpdGUuY29uZmlnLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tICd2aXRlJ1xuaW1wb3J0IHJlYWN0IGZyb20gJ0B2aXRlanMvcGx1Z2luLXJlYWN0J1xuXG4vLyBodHRwczovL3ZpdGVqcy5kZXYvY29uZmlnL1xuZXhwb3J0IGRlZmF1bHQgZGVmaW5lQ29uZmlnKHtcbiAgcGx1Z2luczogW3JlYWN0KCldLFxuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiAnMC4wLjAuMCcsXG4gICAgcG9ydDogNTE3MyxcbiAgICBzdHJpY3RQb3J0OiB0cnVlLFxuICAgIHdhdGNoOiB7XG4gICAgICAvLyBGb3JjZSBwb2xsaW5nIGZvciBXaW5kb3dzL1dTTDIgYmluZC1tb3VudCB2b2x1bWVzLlxuICAgICAgLy8gV2l0aG91dCBgdXNlUG9sbGluZzogdHJ1ZWAgQU5EIGFuIGV4cGxpY2l0IGBpbnRlcnZhbGAsIFZpdGUgZmFsbHMgYmFja1xuICAgICAgLy8gdG8gaW5vdGlmeSBldmVudHMsIHdoaWNoIGZhaWwgd2l0aCBFSU8gd2hlbiB0aGUgRG9ja2VyLW1vdW50ZWQgL2FwcCBwYXRoXG4gICAgICAvLyBiZWNvbWVzIG1vbWVudGFyaWx5IHVuYXZhaWxhYmxlIGR1cmluZyByZWJ1aWxkcyBvciBjb250YWluZXIgcmVzdGFydHMuXG4gICAgICB1c2VQb2xsaW5nOiB0cnVlLFxuICAgICAgaW50ZXJ2YWw6IDMwMCxcbiAgICAgIGJpbmFyeUludGVydmFsOiA2MDAsXG4gICAgICAvLyBFeGNsdWRlIGhlYXZ5IGRpcmVjdG9yaWVzIFx1MjAxNCBwb2xsaW5nIHRoZW0gb24gZXZlcnkgaW50ZXJ2YWwgd2FzdGVzIENQVVxuICAgICAgLy8gYW5kIGNhbiBpdHNlbGYgdHJpZ2dlciBzdGF0IGVycm9ycyBvbiBzdGFsZSBiaW5kLW1vdW50IGlub2Rlcy5cbiAgICAgIGlnbm9yZWQ6IFsnKiovbm9kZV9tb2R1bGVzLyoqJywgJyoqLy5naXQvKionLCAnKiovZGlzdC8qKiddLFxuICAgIH0sXG4gICAgcHJveHk6IHtcbiAgICAgICcvYXBpJzoge1xuICAgICAgICB0YXJnZXQ6ICdodHRwOi8vYmFja2VuZDo4MDAwJyxcbiAgICAgICAgY2hhbmdlT3JpZ2luOiB0cnVlLFxuICAgICAgfVxuICAgIH1cbiAgfVxufSlcbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBOEwsU0FBUyxvQkFBb0I7QUFDM04sT0FBTyxXQUFXO0FBR2xCLElBQU8sc0JBQVEsYUFBYTtBQUFBLEVBQzFCLFNBQVMsQ0FBQyxNQUFNLENBQUM7QUFBQSxFQUNqQixRQUFRO0FBQUEsSUFDTixNQUFNO0FBQUEsSUFDTixNQUFNO0FBQUEsSUFDTixZQUFZO0FBQUEsSUFDWixPQUFPO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxNQUtMLFlBQVk7QUFBQSxNQUNaLFVBQVU7QUFBQSxNQUNWLGdCQUFnQjtBQUFBO0FBQUE7QUFBQSxNQUdoQixTQUFTLENBQUMsc0JBQXNCLGNBQWMsWUFBWTtBQUFBLElBQzVEO0FBQUEsSUFDQSxPQUFPO0FBQUEsTUFDTCxRQUFRO0FBQUEsUUFDTixRQUFRO0FBQUEsUUFDUixjQUFjO0FBQUEsTUFDaEI7QUFBQSxJQUNGO0FBQUEsRUFDRjtBQUNGLENBQUM7IiwKICAibmFtZXMiOiBbXQp9Cg==
