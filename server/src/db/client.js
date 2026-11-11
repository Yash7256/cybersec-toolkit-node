import pg from 'pg'
import { PrismaPg } from '@prisma/adapter-pg'
import { PrismaClient } from '../generated/prisma/client.ts'
import { env } from '../config/env.js'
import { createLogger } from '../utils/logger.js'

const logger = createLogger(env)

export const pool = new pg.Pool({
  connectionString: env.DATABASE_URL,
  max: env.DB_POOL_MAX,
  statement_timeout: env.DB_STATEMENT_TIMEOUT_MS,
  idle_in_transaction_session_timeout: env.DB_IDLE_TX_TIMEOUT_MS,
  connectionTimeoutMillis: 5000,
})

const adapter = new PrismaPg(pool)

export const prisma = new PrismaClient({
  adapter,
  log: [
    { emit: 'event', level: 'warn' },
    { emit: 'event', level: 'error' },
  ],
})

// Only warn/error events; never subscribe to 'query' (it carries parameters).
prisma.$on('warn', (event) => logger.warn({ target: event.target }, event.message))
prisma.$on('error', (event) => logger.error({ target: event.target }, event.message))

export async function pingDb({ timeoutMs = 2000 } = {}) {
  let timeoutId
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(`Database ping timed out after ${timeoutMs}ms`)), timeoutMs)
  })
  try {
    await Promise.race([prisma.$queryRaw`SELECT 1`, timeout])
  } finally {
    clearTimeout(timeoutId)
  }
}

export async function disconnect() {
  await prisma.$disconnect()
  await pool.end()
}
