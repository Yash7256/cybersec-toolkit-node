import { describe, it, expect, beforeEach } from 'vitest'
import { prisma } from '../../src/db/client.js'
import { truncateAll } from './helpers.js'

async function makeUser(clerkUserId = 'constraint_user') {
  return prisma.user.create({
    data: { clerkUserId, email: `${clerkUserId}@example.test` },
  })
}

async function makeRun(user, data = {}) {
  return prisma.toolRun.create({
    data: {
      userId: user.id,
      tool: 'PORT_SCAN',
      target: 'example.com',
      targetKey: 'example.com',
      ...data,
    },
  })
}

const expectRejected = async (promise) => {
  await expect(promise).rejects.toThrow()
}

describe('database constraints reject bad data', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('rejects port 70000', async () => {
    const user = await makeUser()
    const run = await makeRun(user, { status: 'COMPLETED', finishedAt: new Date() })
    await expectRejected(
      prisma.portFinding.create({
        data: { runId: run.id, port: 70000, state: 'OPEN' },
      })
    )
  })

  it('rejects progress_pct 101', async () => {
    const user = await makeUser()
    await expectRejected(makeRun(user, { progressPct: 101 }))
  })

  it('rejects used -1', async () => {
    const user = await makeUser()
    await expectRejected(
      prisma.usageCounter.create({
        data: {
          userId: user.id,
          tool: 'DNS',
          usageDate: new Date(),
          used: -1,
        },
      })
    )
  })

  it('rejects finished_at earlier than started_at', async () => {
    const user = await makeUser()
    await expectRejected(
      makeRun(user, {
        status: 'COMPLETED',
        startedAt: new Date('2026-11-01T10:00:05Z'),
        finishedAt: new Date('2026-11-01T10:00:00Z'),
      })
    )
  })

  it('rejects COMPLETED run with null finished_at', async () => {
    const user = await makeUser()
    await expectRejected(makeRun(user, { status: 'COMPLETED', finishedAt: null }))
  })

  it('rejects email with uppercase', async () => {
    await expectRejected(
      prisma.user.create({
        data: { clerkUserId: 'upper_case_user', email: 'Mixed@Example.TEST' },
      })
    )
  })

  it('rejects CVE id "cve-1"', async () => {
    await expectRejected(
      prisma.cve.create({
        data: { id: 'cve-1', data: { seeded: true }, expiresAt: new Date() },
      })
    )
  })

  it('accepts a well-formed CVE id', async () => {
    const cve = await prisma.cve.create({
      data: { id: 'CVE-2024-12345', data: { seeded: true }, expiresAt: new Date() },
    })
    expect(cve.id).toBe('CVE-2024-12345')
  })
})
