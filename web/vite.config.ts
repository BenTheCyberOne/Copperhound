import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/",
  server: {
    port: 5173,
    proxy: {
      // COPPERHOUND_API points the dev proxy at another server, e.g. http://127.0.0.1:8097.
      "/api": { target: process.env.COPPERHOUND_API ?? "http://127.0.0.1:8080", changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
          graph: ["sigma", "graphology", "graphology-layout-forceatlas2", "@sigma/node-border"],
        },
      },
    },
  },
});
