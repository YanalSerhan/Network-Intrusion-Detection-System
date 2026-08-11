/**
 * Vite build configuration.
 *
 * The bundle is emitted into the FastAPI package so the API serves the SPA
 * directly. That keeps the deployment to a single container with no CORS
 * configuration and no second port to expose.
 *
 * `base` matters: assets are requested from /dashboard/assets/..., so the
 * built index.html must reference them with that prefix or every asset 404s
 * once the app is served from a sub-path rather than the dev-server root.
 */
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const API_TARGET = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  base: "/dashboard/",
  build: {
    outDir: "../src/network_defender/api/static",
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      output: {
        // Charting is by far the largest dependency and is only needed on the
        // overview page. Splitting it keeps the entry bundle small and lets
        // the chart chunk stay cached across deploys that only touch app code.
        manualChunks: {
          charts: ["recharts"],
          react: ["react", "react-dom", "react-router-dom"],
        },
      },
    },
  },
  server: {
    // In dev, Vite serves the SPA and forwards data calls to the running API,
    // so the frontend behaves exactly as it will in production (same origin).
    proxy: {
      "/api": { target: API_TARGET, changeOrigin: true },
      "/ws": { target: API_TARGET, ws: true, changeOrigin: true },
    },
  },
});
