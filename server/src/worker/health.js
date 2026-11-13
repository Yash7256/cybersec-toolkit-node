import http from 'node:http'
import { createHash, timingSafeEqual } from 'node:crypto'
import { metrics } from '../observability/metrics.js'

function tokenMatches(provided, expected) {
  if (!provided || !expected) return false
  const left = createHash('sha256').update(provided).digest()
  const right = createHash('sha256').update(expected).digest()
  return timingSafeEqual(left, right)
}

export function createWorkerHealthServer({ env, pingRedis, pingDb }) {
  return http.createServer(async (req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ status: 'ok' }))
      return
    }
    if (req.url === '/ready') {
      const [redis, db] = await Promise.all([pingRedis(), pingDb?.() ?? true])
      const ready = Boolean(redis && db)
      res.writeHead(ready ? 200 : 503, { 'content-type': 'application/json' })
      res.end(
        JSON.stringify({
          status: ready ? 'ready' : 'not_ready',
          checks: { redis: redis ? 'ok' : 'fail', db: db ? 'ok' : 'fail' },
        })
      )
      return
    }
    if (req.url === '/metrics') {
      if (!env.METRICS_TOKEN) {
        res.writeHead(404)
        res.end()
        return
      }
      const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')
      if (!tokenMatches(match?.[1], env.METRICS_TOKEN)) {
        res.writeHead(401, { 'www-authenticate': 'Bearer', 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { code: 'UNAUTHORIZED', message: 'Unauthorized' } }))
        return
      }
      res.writeHead(200, { 'content-type': metrics.register.contentType, 'cache-control': 'no-store' })
      res.end(await metrics.register.metrics())
      return
    }
    res.writeHead(404)
    res.end()
  })
}
