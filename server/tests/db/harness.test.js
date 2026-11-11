import { describe, it, expect, beforeEach } from 'vitest'
import { prisma, pingDb } from '../../src/db/client.js'
import { truncateAll } from './helpers.js'

describe('test database harness', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('connects to the test database', async () => {
    await pingDb()
    const [row] = await prisma.$queryRaw`SELECT current_database() AS db`
    expect(String(row.db)).toMatch(/_test$/)
  })

  it('has all 11 tables from the design', async () => {
    const rows = await prisma.$queryRaw`
      SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename
    `
    const tables = rows.map((row) => row.tablename)
    expect(tables).toEqual([
      '_prisma_migrations',
      'audit_logs',
      'cves',
      'finding_cves',
      'port_findings',
      'reports',
      'run_results',
      'service_cve_lookups',
      'tool_runs',
      'usage_counters',
      'users',
      'webhook_events',
    ])
  })

  it('truncateAll resets tables', async () => {
    await prisma.user.create({
      data: { clerkUserId: 'truncate_check', email: 'truncate@example.test' },
    })
    await truncateAll()
    expect(await prisma.user.count()).toBe(0)
  })
})
