import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.js'],
    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      DATABASE_URL: 'postgresql://test:test@localhost:5432/cybersec_test',
      DIRECT_URL: 'postgresql://test:test@localhost:5432/cybersec_test',
    },
  },
})
