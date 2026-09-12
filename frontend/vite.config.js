import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  // Fast refresh in dev, JSX transform in the production build.
  plugins: [react()],
})
