import { describe, it, expect, beforeEach } from 'vitest'
import { prisma } from '../../src/db/client.js'
import { findByClerkId, upsertFromClerk, softDelete } from '../../src/db/repos/userRepo.js'
import { truncateAll } from './helpers.js'

describe('userRepo', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('upsertFromClerk twice yields one row', async () => {
    const first = await upsertFromClerk({ clerkUserId: 'user_sync_1', email: 'One@Example.test' })
    const second = await upsertFromClerk({ clerkUserId: 'user_sync_1', email: 'one@example.test' })
    expect(second.id).toBe(first.id)
    expect(await prisma.user.count()).toBe(1)
    expect(second.email).toBe('one@example.test')

    const found = await findByClerkId('user_sync_1')
    expect(found.id).toBe(first.id)
  })

  it('lower-cases the email', async () => {
    const user = await upsertFromClerk({ clerkUserId: 'user_sync_2', email: 'MiXeD.CaSe@Example.TEST' })
    expect(user.email).toBe('mixed.case@example.test')
  })

  it('softDelete nulls the email and frees it for a new user', async () => {
    const user = await upsertFromClerk({ clerkUserId: 'user_sync_3', email: 'shared@example.test' })
    const deleted = await softDelete(user.id)
    expect(deleted.email).toBeNull()
    expect(deleted.isActive).toBe(false)
    expect(deleted.deletedAt).toBeInstanceOf(Date)

    const fresh = await upsertFromClerk({ clerkUserId: 'user_sync_4', email: 'shared@example.test' })
    expect(fresh.email).toBe('shared@example.test')
  })
})

describe('cascade deletes', () => {
  it('removes a user\'s runs, results, findings, reports and usage; keeps audit_logs with NULL actor', async () => {
    const user = await upsertFromClerk({ clerkUserId: 'cascade_user', email: 'cascade@example.test' })
    const run = await prisma.toolRun.create({
      data: {
        userId: user.id,
        tool: 'PORT_SCAN',
        target: 'example.com',
        targetKey: 'example.com',
        status: 'COMPLETED',
        startedAt: new Date('2026-11-01T10:00:00Z'),
        finishedAt: new Date('2026-11-01T10:00:05Z'),
      },
    })
    await prisma.runResult.create({
      data: { runId: run.id, data: { open: 3 } },
    })
    const finding = await prisma.portFinding.create({
      data: { runId: run.id, port: 443, state: 'OPEN', service: 'https' },
    })
    const cve = await prisma.cve.create({
      data: { id: 'CVE-2024-99999', data: { seeded: true }, expiresAt: new Date() },
    })
    await prisma.findingCve.create({
      data: { findingId: finding.id, cveId: cve.id },
    })
    await prisma.report.create({
      data: {
        userId: user.id,
        runId: run.id,
        format: 'JSON',
        storageKey: 'reports/seed.json',
        sizeBytes: 100,
        sha256: 'a'.repeat(64),
      },
    })
    await prisma.usageCounter.create({
      data: { userId: user.id, tool: 'DNS', usageDate: new Date(), used: 1 },
    })
    await prisma.auditLog.create({
      data: { actorId: user.id, action: 'user.deleted', ip: '127.0.0.1' },
    })

    await prisma.user.delete({ where: { id: user.id } })

    expect(await prisma.toolRun.count()).toBe(0)
    expect(await prisma.runResult.count()).toBe(0)
    expect(await prisma.portFinding.count()).toBe(0)
    expect(await prisma.findingCve.count()).toBe(0)
    expect(await prisma.report.count()).toBe(0)
    expect(await prisma.usageCounter.count()).toBe(0)

    const logs = await prisma.auditLog.findMany()
    expect(logs).toHaveLength(1)
    expect(logs[0].actorId).toBeNull()
    expect(logs[0].action).toBe('user.deleted')
  })
})
