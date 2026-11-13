import { Router } from 'express'
import * as shareRepo from '../db/repos/shareRepo.js'
import AppError from '../utils/AppError.js'

function redact(value) {
  if (Array.isArray(value)) return value.map(redact)
  if (!value || typeof value !== 'object') return value
  const out = {}
  for (const [key, child] of Object.entries(value)) {
    if (key === 'abuse_contact') continue
    out[key] = redact(child)
  }
  return out
}

export function publicShareRouter({ limiters } = {}) {
  const router = Router()
  if (limiters?.shareIp) router.use(limiters.shareIp)
  router.get('/:token', async (req, res, next) => {
    try {
      const token = String(req.params.token)
      if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new AppError(404, 'NOT_FOUND', 'Share link not found')
      const share = await shareRepo.findActiveByToken(token)
      if (!share || !share.run || share.run.status !== 'COMPLETED') {
        throw new AppError(404, 'NOT_FOUND', 'Share link not found')
      }
      const data = share.redactAbuseContact ? redact(share.run.result?.data ?? null) : (share.run.result?.data ?? null)
      res.set('Cache-Control', 'no-store').set('X-Robots-Tag', 'noindex, nofollow').json({
        tool: share.run.tool,
        target: share.run.target,
        status: share.run.status,
        createdAt: share.run.createdAt,
        finishedAt: share.run.finishedAt,
        summary: share.run.summary,
        expiresAt: share.expiresAt,
        data,
      })
    } catch (err) { next(err) }
  })
  return router
}
