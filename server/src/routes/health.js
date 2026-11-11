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
      const failed = Object.values(checks).includes('fail')
      res.status(failed ? 503 : 200).json({
        status: failed ? 'not_ready' : 'ready',
        checks,
      })
    }),
  )

  return router
}
