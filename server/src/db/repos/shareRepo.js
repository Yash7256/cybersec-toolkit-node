import { prisma } from '../client.js'
import { createHash, randomBytes } from 'node:crypto'

export function hashToken(token) {
  return createHash('sha256').update(token).digest('hex')
}

export async function create({ runId, userId, ttlDays, redactAbuseContact = true }) {
  const token = randomBytes(32).toString('base64url')
  const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000)
  const share = await prisma.shareLink.create({
    data: {
      token: hashToken(token),
      runId,
      createdBy: userId,
      expiresAt,
      redactAbuseContact,
    },
  })
  return { share, token }
}

export function listForRun(runId, userId) {
  return prisma.shareLink.findMany({
    where: { runId, createdBy: userId },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      expiresAt: true,
      revokedAt: true,
      redactAbuseContact: true,
      createdAt: true,
    },
  })
}

export async function revoke(id, runId, userId) {
  const result = await prisma.shareLink.updateMany({
    where: { id, runId, createdBy: userId, revokedAt: null },
    data: { revokedAt: new Date() },
  })
  return result.count > 0
}

export async function findActiveByToken(token) {
  return prisma.shareLink.findFirst({
    where: {
      token: hashToken(token),
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
    include: { run: { include: { result: true } } },
  })
}

export async function countActiveForRun(runId, userId) {
  return prisma.shareLink.count({
    where: { runId, createdBy: userId, revokedAt: null, expiresAt: { gt: new Date() } },
  })
}

export async function deleteExpired() {
  const result = await prisma.shareLink.deleteMany({
    where: { OR: [{ expiresAt: { lt: new Date() } }, { revokedAt: { lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }] },
  })
  return result.count
}
