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
        } catch (err) {
          checks[name] = { ok: false, error: err.message }
        }
      }
      const failed = Object.values(checks).some((result) => result?.ok === false)
      res.status(failed ? 503 : 200).json({
        status: failed ? 'not_ready' : 'ready',
        checks,
      })
    }),
  )

  return router
}
