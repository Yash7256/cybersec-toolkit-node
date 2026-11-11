import { defineConfig } from 'vitest/config'

// Dummy DB URLs so unit tests can parse env without a real database.
const unitEnv = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'silent',
  DATABASE_URL: 'postgresql://test:test@localhost:5432/cybersec_test',
  DIRECT_URL: 'postgresql://test:test@localhost:5432/cybersec_test',
}

export default defineConfig({
  test: {
    environment: 'node',
    projects: [
      {
        test: {
          name: 'unit',
          include: ['tests/*.test.js'],
          env: unitEnv,
        },
      },
      {
        test: {
          name: 'db',
          include: ['tests/db/**/*.test.js'],
          env: { NODE_ENV: 'test', LOG_LEVEL: 'silent' },
          // globalSetup points DATABASE_URL/DIRECT_URL at TEST_DATABASE_URL
          // (guarded to end with _test) and applies migrations to it.
          globalSetup: ['tests/setup/globalSetup.js'],
        },
      },
    ],
  },
})
