import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// FE-1: the production build is committed to frontend/dist/ and served verbatim by
// frontend/serve.py, so judges get a working dashboard from `python3 serve.py 5173`
// with NO Vite dev server and NO `npm install`. `npm run dev` still works for devs.
//
// CSP note: frontend/serve.py sends `script-src 'self'` with NO 'unsafe-inline' /
// 'unsafe-eval'. Two build settings keep the output compatible:
//   * modulePreload.polyfill = false  -> no inline <script> preload polyfill
//   * assetsInlineLimit = 0           -> no `data:` asset URLs in CSS/JS
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: { port: 5173, host: "0.0.0.0" },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        // Stable, non-hashed names so the committed bundle diffs cleanly and
        // serve.py / index.html never need updating after a rebuild.
        entryFileNames: "assets/app.js",
        chunkFileNames: "assets/[name].js",
        assetFileNames: "assets/[name][extname]",
      },
    },
  },
});
