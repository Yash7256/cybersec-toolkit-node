import { defineConfig } from 'vitest/config'

// Dummy but well-formed values so tests parse env without real credentials.
const unitEnv = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'silent',
  DATABASE_URL: 'postgresql://test:test@localhost:5432/cybersec_test',
  DIRECT_URL: 'postgresql://test:test@localhost:5432/cybersec_test',
  CLERK_PUBLISHABLE_KEY: 'pk_test_ZXhhbXBsZS5jb20k',
  CLERK_SECRET_KEY: 'sk_test_cGxhY2Vob2xkZXI=',
  CLERK_WEBHOOK_SIGNING_SECRET: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
  FREE_DAILY_LIMIT: '5',
  PAID_DAILY_LIMIT: '100',
  REDIS_URL: 'redis://localhost:6379/1',
  TEST_REDIS_URL: 'redis://localhost:6379/1',
  ALLOW_PRIVATE_TARGETS: 'false',
}

const dbEnv = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'silent',
  CLERK_PUBLISHABLE_KEY: unitEnv.CLERK_PUBLISHABLE_KEY,
  CLERK_SECRET_KEY: unitEnv.CLERK_SECRET_KEY,
  CLERK_WEBHOOK_SIGNING_SECRET: unitEnv.CLERK_WEBHOOK_SIGNING_SECRET,
  REDIS_URL: unitEnv.REDIS_URL,
  TEST_REDIS_URL: unitEnv.TEST_REDIS_URL,
  ALLOW_PRIVATE_TARGETS: unitEnv.ALLOW_PRIVATE_TARGETS,
}

export default defineConfig({
  test: {
    environment: 'node',
    projects: [
      {
        test: {
          name: 'unit',
          include: ['tests/*.test.js', 'tests/unit/**/*.test.js'],
          env: unitEnv,
        },
      },
      {
        test: {
          name: 'db',
          include: ['tests/db/**/*.test.js', 'tests/api/**/*.test.js', 'tests/live/**/*.test.js'],
          env: dbEnv,
          // Every DB test shares one database and calls truncateAll(); running
          // files in parallel lets one file's TRUNCATE wipe another's fixtures.
          fileParallelism: false,
          // globalSetup points DATABASE_URL/DIRECT_URL at TEST_DATABASE_URL
          // (guarded to end with _test) and applies migrations to it.
          globalSetup: ['tests/setup/globalSetup.js'],
        },
      },
      {
        test: {
          name: 'integration',
          include: ['tests/integration/**/*.test.js'],
          // Integration files share one Postgres database and Redis DB index.
          fileParallelism: false,
          env: { ...unitEnv, ...dbEnv, DATABASE_URL: 'postgresql://cybersec:cybersec@localhost:5433/cybersec_test', DIRECT_URL: 'postgresql://cybersec:cybersec@localhost:5433/cybersec_test', QUEUE_PREFIX: 'cst_phase6_test' },
          globalSetup: ['tests/setup/globalSetup.js'],
        },
      },
    ],
  },
})
