import { Router } from 'express'
import asyncHandler from '../utils/asyncHandler.js'

const readinessChecks = []

export function registerReadinessCheck(name, check) {
  readinessChecks.push({ name, check })
}

export default function healthRouter() {
  const router = Router()

  router.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    })
  })

  router.get(
    '/ready',
    asyncHandler(async (req, res) => {
      const checks = {}
      for (const { name, check } of readinessChecks) {
        try {
          checks[name] = await check()
        } catch {
          // No internals leaked: a failed dependency is reported as 'fail' only.
          checks[name] = 'fail'
        }
      }
      const dbFailed = checks.db === 'fail'
      const redisFailed = checks.redis === 'fail' || checks.queue === 'fail'
      const degraded = !dbFailed && Object.values(checks).includes('fail')
      res.status(dbFailed || redisFailed ? 503 : 200).json({
        status: dbFailed || redisFailed ? 'not_ready' : degraded ? 'degraded' : 'ready',
        checks,
      })
    }),
  )

  return router
}
