import { prisma } from '../client.js'
import { env } from '../../config/env.js'
import { createLogger } from '../../utils/logger.js'

const logger = createLogger(env)

// Audit writes must never break a request: swallow failures and log them.
export async function log({
  actorId,
  action,
  entityType,
  entityId,
  ip,
  userAgent,
  metadata,
} = {}) {
  try {
    await prisma.auditLog.create({
      data: {
        actorId: actorId ?? null,
        action,
        entityType: entityType ?? null,
        entityId: entityId === undefined || entityId === null ? null : String(entityId),
        ip: ip ?? null,
        userAgent: userAgent ? String(userAgent).slice(0, 300) : null,
        ...(metadata !== undefined ? { metadata } : {}),
      },
    })
  } catch (err) {
    logger.error({ err, action }, 'Failed to write audit log')
  }
}
