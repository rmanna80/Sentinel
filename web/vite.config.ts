/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Sentinel server listens on 127.0.0.1:8765 and rejects unexpected Host headers,
// so the dev proxy rewrites Host (changeOrigin) to the server's own address.
const API_TARGET = process.env.SENTINEL_API ?? "http://127.0.0.1:8765";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "assets",
    sourcemap: false,
    chunkSizeWarningLimit: 1600,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
