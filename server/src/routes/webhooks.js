import { Router } from 'express'
import { verifyWebhook } from '@clerk/express/webhooks'
import { env as defaultEnv } from '../config/env.js'
import { createLogger } from '../utils/logger.js'
import AppError from '../utils/AppError.js'
import asyncHandler from '../utils/asyncHandler.js'
import * as defaultWebhookRepo from '../db/repos/webhookRepo.js'
import * as defaultUserRepo from '../db/repos/userRepo.js'
import * as defaultAuditRepo from '../db/repos/auditRepo.js'
import { handleClerkEvent } from '../services/clerkSync.js'

export default function webhookRouter({
  env = defaultEnv,
  logger = createLogger(env),
  repo = defaultWebhookRepo,
  userRepo = defaultUserRepo,
  auditRepo = defaultAuditRepo,
  handler = handleClerkEvent,
} = {}) {
  const router = Router()

  router.post(
    '/clerk',
    asyncHandler(async (req, res) => {
      const signingSecret = env.CLERK_WEBHOOK_SIGNING_SECRET
      if (!signingSecret) {
        throw new AppError(503, 'WEBHOOKS_NOT_CONFIGURED', 'Webhooks are not configured')
      }

      let event
      try {
        event = await verifyWebhook(req, { signingSecret })
      } catch {
        throw new AppError(400, 'INVALID_SIGNATURE', 'Invalid webhook signature')
      }

      const svixId = req.get('svix-id')
      const type = event.type

      const claim = await repo.claim({ id: svixId, source: 'clerk', eventType: type })
      if (claim.duplicate) {
        logger.info({ svixId, type, outcome: 'duplicate' }, 'clerk webhook duplicate')
        res.json({ received: true, duplicate: true })
        return
      }

      try {
        const result = await handler(event, { userRepo, auditRepo })
        await repo.markProcessed(svixId)
        logger.info({ svixId, type, outcome: 'processed' }, 'clerk webhook processed')
        res.json({ received: true, duplicate: false, handled: result.handled })
      } catch (err) {
        await repo.markFailed(svixId, err.message)
        logger.error({ svixId, type, outcome: 'failed' }, 'clerk webhook failed')
        throw err
      }
    })
  )

  return router
}
