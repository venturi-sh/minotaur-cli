import { defineConfig } from 'vitest/config';

// Coverage counts every file `include` matches, not only the ones a test happened to import.
export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      exclude: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'src/**/index.ts', 'src/bin.ts'],
      reporter: ['text', 'json-summary'],
    },
  },
});
