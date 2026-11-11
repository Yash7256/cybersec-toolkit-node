import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import 'dotenv/config'

const serverRoot = fileURLToPath(new URL('../../', import.meta.url))

export default function setup() {
  const testUrl = process.env.TEST_DATABASE_URL
  if (!testUrl) {
    throw new Error('TEST_DATABASE_URL must be set to run database tests')
  }

  // Hard guard: never run migrations or tests against a non-test database.
  const databaseName = new URL(testUrl).pathname.replace(/^\//, '')
  if (!databaseName.endsWith('_test')) {
    throw new Error(
      `Refusing to run database tests: TEST_DATABASE_URL database "${databaseName}" does not end with _test`
    )
  }

  // Point the runtime client and the Prisma CLI at the test database.
  process.env.DATABASE_URL = testUrl
  process.env.DIRECT_URL = testUrl

  // Apply migrations once before any test file runs.
  execFileSync('npx', ['prisma', 'migrate', 'deploy'], {
    cwd: serverRoot,
    stdio: 'inherit',
    env: process.env,
  })
}
