/**
 * Vitest configuration.
 *
 * Kept separate from vite.config.ts because the build config is typed by Vite,
 * which does not know the `test` key; merging them makes `tsc -b` fail on the
 * production build.
 */
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
