import { describe, it, expect, beforeEach } from 'vitest'
import { prisma } from '../../src/db/client.js'
import { consume, getToday } from '../../src/db/repos/usageRepo.js'
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
  })

  it('keeps counters independent per tool', async () => {
    const user = await makeUser()
    const a1 = await consume({ userId: user.id, tool: 'DNS', limit: 1 })
    const b1 = await consume({ userId: user.id, tool: 'WHOIS', limit: 1 })
    const a2 = await consume({ userId: user.id, tool: 'DNS', limit: 1 })
    expect(a1).toEqual({ allowed: true, used: 1 })
    expect(b1).toEqual({ allowed: true, used: 1 })
    expect(a2).toEqual({ allowed: false, used: 1 })
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
    expect(today).toEqual({ allowed: true, used: 1 })
    expect(await getToday({ userId: user.id })).toEqual([{ tool: 'DNS', used: 1 }])
  })

  it('allows again when the limit is raised', async () => {
    const user = await makeUser()
    for (let i = 0; i < 5; i += 1) {
      await consume({ userId: user.id, tool: 'PING', limit: 5 })
    }
    const result = await consume({ userId: user.id, tool: 'PING', limit: 10 })
    expect(result).toEqual({ allowed: true, used: 6 })
  })
})
