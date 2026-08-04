import { defineConfig } from 'vitest/config';

// Dedicated config so the runner does NOT load vite.config.ts (its Worker + Flue
// plugins are incompatible with the node test environment). Tests are pure logic.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
