import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { prisma } from '../../src/db/client.js'
import * as userRepo from '../../src/db/repos/userRepo.js'
import * as runRepo from '../../src/db/repos/runRepo.js'
import { truncateAll } from './helpers.js'

async function makeUser(id) {
  return userRepo.upsertFromClerk({ clerkUserId: id, email: `${id}@example.test`, tier: 'FREE' })
}

async function seedRuns(userId, count, createdAt = new Date()) {
  await prisma.toolRun.createMany({
    data: Array.from({ length: count }, (_, index) => ({
      userId,
      tool: 'DNS',
      target: `example-${index}.com`,
      targetKey: `example-${index}.com`,
      status: 'COMPLETED',
      createdAt,
      finishedAt: createdAt,
    })),
  })
}

describe('run repository', () => {
  beforeEach(() => truncateAll())
  afterAll(() => prisma.$disconnect())

  it('paginates keyset pages without duplicates when createdAt ties', async () => {
    const user = await makeUser('keyset_user')
    await seedRuns(user.id, 30)

    const seen = new Set()
    let cursor = null
    for (let page = 0; page < 5; page += 1) {
      const rows = await runRepo.listForUser({ userId: user.id, limit: 10, cursor })
      for (const row of rows) seen.add(row.id)
      if (rows.length < 10) break
      cursor = { id: rows.at(-1).id, createdAt: rows.at(-1).createdAt }
    }
    expect(seen.size).toBe(30)
  })

  it('caps page size at 50', async () => {
    const user = await makeUser('cap_user')
    await seedRuns(user.id, 60)
    const rows = await runRepo.listForUser({ userId: user.id, limit: 500 })
    expect(rows).toHaveLength(50)
  })

  it('filters by tool and status', async () => {
    const user = await makeUser('filter_user')
    await seedRuns(user.id, 2)
    await prisma.toolRun.create({
      data: { userId: user.id, tool: 'SSL', target: 'ssl.example', targetKey: 'ssl.example', status: 'FAILED', finishedAt: new Date() },
    })
    expect(await runRepo.listForUser({ userId: user.id, tool: 'SSL' })).toHaveLength(1)
    expect(await runRepo.listForUser({ userId: user.id, status: 'FAILED' })).toHaveLength(1)
  })

  it('is IDOR-proof for reads and deletes', async () => {
    const owner = await makeUser('owner_user')
    const other = await makeUser('other_user')
    const run = await runRepo.start({
      userId: owner.id,
      tool: 'DNS',
      target: 'example.com',
      targetKey: 'example.com',
    })
    expect(await runRepo.findByIdForUser(run.id, other.id)).toBeNull()
    expect(await runRepo.deleteForUser(run.id, other.id)).toBe(false)
    expect(await runRepo.findByIdForUser(run.id, owner.id)).not.toBeNull()
    expect(await runRepo.deleteForUser(run.id, owner.id)).toBe(true)
  })

  it('writes run_results and status atomically', async () => {
    const user = await makeUser('complete_user')
    const run = await runRepo.start({
      userId: user.id,
      tool: 'DNS',
      target: 'example.com',
      targetKey: 'example.com',
    })
    await runRepo.complete(run.id, { data: { records: [] }, summary: { recordCount: 0 } })
    const stored = await prisma.toolRun.findUnique({ where: { id: run.id }, include: { result: true } })
    expect(stored.status).toBe('COMPLETED')
    expect(stored.finishedAt).not.toBeNull()
    expect(stored.result.data).toEqual({ records: [] })

    const second = await runRepo.start({
      userId: user.id,
      tool: 'DNS',
      target: 'atomic.example',
      targetKey: 'atomic.example',
    })
    await prisma.runResult.create({ data: { runId: second.id, data: { original: true } } })
    await expect(
      runRepo.complete(second.id, { data: { replacement: true } })
    ).rejects.toThrow()
    const afterFailure = await prisma.toolRun.findUnique({ where: { id: second.id } })
    expect(afterFailure.status).toBe('RUNNING')
    const result = await prisma.runResult.findUnique({ where: { runId: second.id } })
    expect(result.data).toEqual({ original: true })
  })
})
