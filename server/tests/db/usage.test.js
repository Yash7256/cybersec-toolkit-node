import { describe, it, expect, beforeEach } from 'vitest'
import { prisma } from '../../src/db/client.js'
import { consume, getToday, refund } from '../../src/db/repos/usageRepo.js'
import { utcDate } from '../../src/config/limits.js'
import { truncateAll } from './helpers.js'

async function makeUser(clerkUserId = 'quota_user') {
  return prisma.user.create({
    data: { clerkUserId, email: `${clerkUserId}@example.test` },
  })
}

describe('usageRepo.consume', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('allows exactly the limit under 50 concurrent calls', async () => {
    const user = await makeUser()

    const results = await Promise.all(
      Array.from({ length: 50 }, () => consume({ userId: user.id, tool: 'DNS', limit: 5 }))
    )

    const allowed = results.filter((r) => r.allowed)
    const denied = results.filter((r) => !r.allowed)
    expect(allowed).toHaveLength(5)
    expect(denied).toHaveLength(45)

    const counter = await prisma.usageCounter.findUnique({
      where: {
        userId_tool_usageDate: {
          userId: user.id,
          tool: 'DNS',
          usageDate: new Date(new Date().toISOString().slice(0, 10)),
        },
      },
    })
    expect(counter.used).toBe(5)
    expect(denied.every((r) => r.used === 5)).toBe(true)
    expect(results.every((r) => /^\d{4}-\d{2}-\d{2}$/.test(r.usageDate))).toBe(true)
  })

  it('returns the usageDate it consumed', async () => {
    const user = await makeUser()
    const result = await consume({ userId: user.id, tool: 'DNS', limit: 5 })
    expect(result).toMatchObject({ allowed: true, used: 1 })
    expect(result.usageDate).toBe(utcDate())
  })

  it('keeps counters independent per tool', async () => {
    const user = await makeUser()
    const a1 = await consume({ userId: user.id, tool: 'DNS', limit: 1 })
    const b1 = await consume({ userId: user.id, tool: 'WHOIS', limit: 1 })
    const a2 = await consume({ userId: user.id, tool: 'DNS', limit: 1 })
    expect(a1).toMatchObject({ allowed: true, used: 1 })
    expect(b1).toMatchObject({ allowed: true, used: 1 })
    expect(a2).toMatchObject({ allowed: false, used: 1 })
  })

  it('keeps counters independent per usage_date', async () => {
    const user = await makeUser()
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000)
    await prisma.usageCounter.create({
      data: {
        userId: user.id,
        tool: 'DNS',
        usageDate: yesterday,
        used: 5,
      },
    })

    const today = await consume({ userId: user.id, tool: 'DNS', limit: 5 })
    expect(today).toMatchObject({ allowed: true, used: 1 })
    expect(await getToday({ userId: user.id })).toEqual([{ tool: 'DNS', used: 1 }])
  })

  it('allows again when the limit is raised', async () => {
    const user = await makeUser()
    for (let i = 0; i < 5; i += 1) {
      await consume({ userId: user.id, tool: 'PING', limit: 5 })
    }
    const result = await consume({ userId: user.id, tool: 'PING', limit: 10 })
    expect(result).toMatchObject({ allowed: true, used: 6 })
  })
})

describe('usageRepo.refund', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('decrements by exactly one on the right day', async () => {
    const user = await makeUser()
    await consume({ userId: user.id, tool: 'DNS', limit: 5 })
    const second = await consume({ userId: user.id, tool: 'DNS', limit: 5 })
    expect(second.used).toBe(2)

    const refunded = await refund({ userId: user.id, tool: 'DNS', usageDate: second.usageDate })
    expect(refunded).toBe(true)

    const row = await prisma.usageCounter.findFirst({
      where: { userId: user.id, tool: 'DNS' },
    })
    expect(row.used).toBe(1)
  })

  it('never goes below zero and reports a missing row', async () => {
    const user = await makeUser()
    await consume({ userId: user.id, tool: 'DNS', limit: 5 })

    const today = utcDate()
    await refund({ userId: user.id, tool: 'DNS', usageDate: today })
    await refund({ userId: user.id, tool: 'DNS', usageDate: today })
    await refund({ userId: user.id, tool: 'DNS', usageDate: today })

    const row = await prisma.usageCounter.findFirst({
      where: { userId: user.id, tool: 'DNS' },
    })
    expect(row.used).toBe(0)
    expect(await refund({ userId: user.id, tool: 'WHOIS', usageDate: today })).toBe(false)
  })

  it("refunding yesterday does not touch today's row", async () => {
    const user = await makeUser()
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000)
    const yesterdayKey = yesterday.toISOString().slice(0, 10)
    await prisma.usageCounter.create({
      data: { userId: user.id, tool: 'DNS', usageDate: yesterday, used: 5 },
    })
    await prisma.usageCounter.create({
      data: { userId: user.id, tool: 'DNS', usageDate: new Date(utcDate()), used: 2 },
    })

    expect(await refund({ userId: user.id, tool: 'DNS', usageDate: yesterdayKey })).toBe(true)

    const rows = await prisma.usageCounter.findMany({
      where: { userId: user.id, tool: 'DNS' },
      orderBy: { usageDate: 'asc' },
    })
    expect(rows.map((row) => row.used)).toEqual([4, 2])
  })
})
