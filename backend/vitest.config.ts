import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Each test file gets an isolated in-memory-ish database via env (see
    // tests/setup.ts). Run serially so the shared SQLite file is deterministic.
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup.ts'],
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
