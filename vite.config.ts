/// <reference types="vitest/config" />
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-protocol-compose/',
  test: {
    // Keep Playwright e2e specs out of the vitest run; they are driven by
    // `npm run test:a11y` (playwright test) instead.
    exclude: ['**/node_modules/**', '**/dist/**', 'e2e/**'],
  },
});
