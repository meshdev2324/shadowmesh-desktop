import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { join, resolve } from "path";

export default defineConfig({
  root: join(__dirname, "src/renderer"),
  base: "./",
  build: {
    outDir: join(__dirname, "dist/renderer"),
    emptyOutDir: true,
    sourcemap: true,
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
      "@types": resolve(__dirname, "src/types"),
      "@renderer": resolve(__dirname, "src/renderer"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: [resolve(__dirname, "vitest.setup.tsx")],
    include: ["**/*.{test,spec}.{ts,tsx}"],
  },
});
