import pg from 'pg'
import { PrismaPg } from '@prisma/adapter-pg'
import { PrismaClient } from '../generated/prisma/client.ts'
import { env } from '../config/env.js'
import { createLogger } from '../utils/logger.js'

const logger = createLogger(env)

// Prisma Postgres' pooled endpoint rejects extra startup parameters with
// "Failed to connect to upstream database", so only send the session timeouts
// to endpoints that accept them (e.g. the direct endpoint or local Postgres).
const dbHostname = (() => {
  try {
    return new URL(env.DATABASE_URL).hostname
  } catch {
    return ''
  }
})()
const rejectsStartupParams = /(^|\.)pooled\.db\.prisma\.io$/i.test(dbHostname)
const sessionTimeouts = rejectsStartupParams
  ? { query_timeout: env.DB_STATEMENT_TIMEOUT_MS }
  : {
      statement_timeout: env.DB_STATEMENT_TIMEOUT_MS,
      idle_in_transaction_session_timeout: env.DB_IDLE_TX_TIMEOUT_MS,
    }

export const pool = new pg.Pool({
  connectionString: env.DATABASE_URL,
  max: env.DB_POOL_MAX,
  ...sessionTimeouts,
  connectionTimeoutMillis: 5000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10_000,
  idleTimeoutMillis: 30_000,
})

// A dropped idle connection (pooler restart, network blip) arrives as an
// 'error' event on the pool; without a listener Node treats it as uncaught.
pool.on('error', (err) => {
  logger.error({ err, target: 'pg-pool' }, 'Idle database connection error')
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

const TRANSIENT_CODES = new Set([
  'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE',
  '08000', '08003', '08006', '57P01', '57P02', '57P03',
])

function isTransientDbError(err) {
  if (TRANSIENT_CODES.has(err?.code)) return true
  return /Failed to connect to upstream database|Connection terminated|connection (?:closed|reset)|timed out/i
    .test(String(err?.message ?? ''))
}

export async function pingDb({ timeoutMs = 2000, retries = 2 } = {}) {
  for (let attempt = 0; ; attempt += 1) {
    let timeoutId
    const timeout = new Promise((_, reject) => {
      timeoutId = setTimeout(() => reject(new Error(`Database ping timed out after ${timeoutMs}ms`)), timeoutMs)
    })
    try {
      await Promise.race([prisma.$queryRaw`SELECT 1`, timeout])
      return
    } catch (err) {
      if (attempt >= retries || !isTransientDbError(err)) throw err
      logger.warn({ attempt: attempt + 1 }, 'Transient database connection failure; retrying ping')
      await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** attempt))
    } finally {
      clearTimeout(timeoutId)
    }
  }
}

export async function disconnect() {
  await prisma.$disconnect()
  await pool.end()
}
