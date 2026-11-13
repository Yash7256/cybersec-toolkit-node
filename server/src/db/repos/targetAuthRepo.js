import { getDomain } from 'tldts'
import { prisma } from '../client.js'
import { getProducerConnection } from '../../queue/connections.js'
import { env as defaultEnv } from '../../config/env.js'
import * as auditRepo from './auditRepo.js'

export function registrableDomain(value) {
  const domain = getDomain(String(value).replace(/\.$/, '').toLowerCase())
  return domain || String(value).replace(/\.$/, '').toLowerCase()
}

export async function getActive(userId, domain) {
  return prisma.targetAuthorization.findFirst({
    where: { userId, registrableDomain: registrableDomain(domain), status: 'APPROVED' },
  })
}

export async function list(userId) {
  return prisma.targetAuthorization.findMany({
    where: { userId }, orderBy: { createdAt: 'desc' },
  })
}

export async function attest(userId, domain, { env = defaultEnv, ip, userAgent } = {}) {
  const normalized = registrableDomain(domain)
  const redis = getProducerConnection()
  const key = `${env.QUEUE_PREFIX}:auth-attest:${userId}:${normalized}`
  const claimed = await redis.set(key, '1', 'NX', 'EX', env.WEBAPP_AUTH_ATTESTATION_COOLDOWN_SEC)
  if (!claimed) return { cooldown: true, record: null }
  const record = await prisma.targetAuthorization.upsert({
    where: { userId_registrableDomain: { userId, registrableDomain: normalized } },
    create: { userId, registrableDomain: normalized, method: 'ATTESTATION', status: 'APPROVED' },
    update: { method: 'ATTESTATION', status: 'APPROVED', revokedAt: null },
  })
  await auditRepo.log({ actorId: userId, action: 'target.authorized', entityType: 'TargetAuthorization', entityId: record.id, ip, userAgent, metadata: { domain: normalized, method: 'ATTESTATION' } })
  return { cooldown: false, record }
}

export async function revoke(userId, domain, { ip, userAgent } = {}) {
  const normalized = registrableDomain(domain)
  const record = await prisma.targetAuthorization.updateMany({
    where: { userId, registrableDomain: normalized },
    data: { status: 'REVOKED', revokedAt: new Date() },
  })
  if (record.count > 0) await auditRepo.log({ actorId: userId, action: 'target.authorization_revoked', entityType: 'TargetAuthorization', ip, userAgent, metadata: { domain: normalized } })
  return record.count > 0
}
