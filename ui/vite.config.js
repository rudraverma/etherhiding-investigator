import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    // Dev proxy so `npm run dev` talks to a locally running API.
    proxy: {
      '/api': { target: 'http://localhost:8094', changeOrigin: true },
    },
  },
  build: { outDir: 'dist', sourcemap: false },
});
