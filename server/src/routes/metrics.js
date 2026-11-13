import { Router } from 'express'
import { createHash, timingSafeEqual } from 'node:crypto'
import { metrics } from '../observability/metrics.js'

function tokenMatches(provided, expected) {
  if (!provided || !expected) return false
  const left = createHash('sha256').update(provided).digest()
  const right = createHash('sha256').update(expected).digest()
  return timingSafeEqual(left, right)
}

export default function metricsRouter({ env } = {}) {
  const router = Router()
  router.get('/', async (req, res) => {
    if (!env?.METRICS_TOKEN) return res.sendStatus(404)
    const match = /^Bearer (.+)$/.exec(req.get('authorization') ?? '')
    if (!tokenMatches(match?.[1], env.METRICS_TOKEN)) {
      return res.status(401).set('WWW-Authenticate', 'Bearer').json({
        error: { code: 'UNAUTHORIZED', message: 'Unauthorized', requestId: req.id },
      })
    }
    res.set('Cache-Control', 'no-store')
    res.set('Content-Type', metrics.register.contentType)
    return res.send(await metrics.register.metrics())
  })
  return router
}
