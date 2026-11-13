import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { prisma } from '../../src/db/client.js'
import * as userRepo from '../../src/db/repos/userRepo.js'
import * as runRepo from '../../src/db/repos/runRepo.js'
import { truncateAll } from './helpers.js'

async function makeUser(id = 'phase6_user') {
  return userRepo.upsertFromClerk({ clerkUserId: id, email: `${id}@example.test`, tier: 'FREE' })
}

describe('Phase 6 fenced run lifecycle', () => {
  beforeEach(() => truncateAll())
  afterAll(() => prisma.$disconnect())

  it('enforces the per-user active cap under parallel inserts', async () => {
    const user = await makeUser()
    const results = await Promise.all(Array.from({ length: 20 }, (_, index) => runRepo.createQueuedWithCap({ userId: user.id, tool: 'DNS', target: `example-${index}.com`, targetKey: `example-${index}.com`, options: {}, quotaDate: new Date(), cap: 2 })))
    expect(results.filter(Boolean)).toHaveLength(2)
    expect(await runRepo.countActiveForUser(user.id)).toBe(2)
  })

  it('allows exactly one claimant and fences the old worker after reclaim', async () => {
    const user = await makeUser('claim_user')
    const created = await runRepo.createQueuedWithCap({ userId: user.id, tool: 'DNS', target: 'example.com', targetKey: 'example.com', options: {}, quotaDate: new Date(), cap: 2 })
    const claims = await Promise.all(Array.from({ length: 10 }, () => runRepo.claim({ runId: created.id, workerId: 'worker-a' })))
    expect(claims.filter(Boolean)).toHaveLength(1)
    await prisma.$executeRaw`UPDATE tool_runs SET heartbeat_at=now() - interval '10 minutes' WHERE id=${created.id}::uuid`
    const reclaimed = await runRepo.reclaimStale({ stallSec: 1, maxAttempts: 2, limit: 10 })
    expect(reclaimed).toHaveLength(1)
    const second = await runRepo.claim({ runId: created.id, workerId: 'worker-b' })
    expect(second).toBeTruthy()
    expect(await runRepo.heartbeat({ runId: created.id, workerId: 'worker-a', attempt: 1, progressPct: 90 })).toBeNull()
    expect(await runRepo.completeFenced({ runId: created.id, workerId: 'worker-a', attempt: 1, data: { stale: true } })).toBe(false)
    expect(await prisma.runResult.count()).toBe(0)
  })

  it('refunds quota exactly once in parallel', async () => {
    const user = await makeUser('refund_user')
    await prisma.usageCounter.create({ data: { userId: user.id, tool: 'DNS', usageDate: new Date(), used: 1 } })
    const run = await prisma.toolRun.create({ data: { userId: user.id, tool: 'DNS', target: 'example.com', targetKey: 'example.com', status: 'FAILED', quotaDate: new Date(), quotaRefunded: false, finishedAt: new Date() } })
    const results = await Promise.all(Array.from({ length: 10 }, () => runRepo.refundOnce(run.id)))
    expect(results.filter(Boolean)).toHaveLength(1)
    expect((await prisma.usageCounter.findFirst({ where: { userId: user.id, tool: 'DNS' } })).used).toBe(0)
  })
})
