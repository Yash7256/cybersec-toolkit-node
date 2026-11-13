import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { prisma } from '../../src/db/client.js'
import * as userRepo from '../../src/db/repos/userRepo.js'
import { runRetention } from '../../src/maintenance/retention.js'
import { truncateAll } from './helpers.js'

describe('Phase 6 retention', () => {
  beforeEach(() => truncateAll())
  afterAll(() => prisma.$disconnect())

  it('deletes only expired terminal runs and preserves active runs', async () => {
    const free = await userRepo.upsertFromClerk({ clerkUserId: 'retention_free', email: 'retention_free@example.test', tier: 'FREE' })
    const old = new Date(Date.now() - 100 * 86400000)
    await prisma.toolRun.createMany({ data: [
      { userId: free.id, tool: 'DNS', target: 'old.test', targetKey: 'old.test', status: 'COMPLETED', createdAt: old, finishedAt: old },
      { userId: free.id, tool: 'DNS', target: 'active.test', targetKey: 'active.test', status: 'RUNNING', createdAt: old },
    ] })
    const result = await runRetention({ env: { RETENTION_DAYS_FREE: 90, RETENTION_DAYS_PAID: 365, RETENTION_BATCH_SIZE: 10, RETENTION_MAX_BATCHES: 2, RETENTION_DRY_RUN: false }, now: new Date() })
    expect(result.toolRuns).toBe(1)
    expect(await prisma.toolRun.count({ where: { status: 'RUNNING' } })).toBe(1)
  })

  it('dry run reports without deleting', async () => {
    const user = await userRepo.upsertFromClerk({ clerkUserId: 'retention_dry', email: 'retention_dry@example.test', tier: 'FREE' })
    const old = new Date(Date.now() - 100 * 86400000)
    await prisma.toolRun.create({ data: { userId: user.id, tool: 'DNS', target: 'dry.test', targetKey: 'dry.test', status: 'FAILED', createdAt: old, finishedAt: old } })
    const result = await runRetention({ env: { RETENTION_DAYS_FREE: 90, RETENTION_DAYS_PAID: 365, RETENTION_BATCH_SIZE: 10, RETENTION_MAX_BATCHES: 2, RETENTION_DRY_RUN: true }, now: new Date() })
    expect(result).toMatchObject({ toolRuns: 1, dryRun: true })
    expect(await prisma.toolRun.count()).toBe(1)
  })
})
