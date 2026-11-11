import { Router } from 'express'
import { createAttachUser } from '../middleware/attachUser.js'
import AppError from '../utils/AppError.js'
import asyncHandler from '../utils/asyncHandler.js'
import { env as defaultEnv } from '../config/env.js'
import { limitFor, nextResetAt, utcDate } from '../config/limits.js'
import * as userRepo from '../db/repos/userRepo.js'
import * as usageRepo from '../db/repos/usageRepo.js'
import { ToolName } from '../generated/prisma/enums.ts'

const NO_STORE = 'no-store'

export default function userRouter({
  auth,
  attachUser,
  clerkClient,
  env = defaultEnv,
  limiters,
} = {}) {
  const router = Router()
  const attach = attachUser ?? createAttachUser({ clerkClient })

  router.use(auth.requireAuth, attach)
  if (limiters?.userGeneral) router.use(limiters.userGeneral)

  router.get(
    '/me',
    asyncHandler(async (req, res) => {
      const user = await userRepo.findById(req.user.id)
      if (!user) throw AppError.notFound('User not found')

      res.set('Cache-Control', NO_STORE).json({
        id: user.id,
        email: user.email,
        tier: user.tier,
        role: user.role,
        createdAt: user.createdAt,
      })
    })
  )

  router.get(
    '/usage',
    asyncHandler(async (req, res) => {
      const [rows, now] = await Promise.all([
        usageRepo.getToday({ userId: req.user.id }),
        Promise.resolve(new Date()),
      ])

      const usedByTool = new Map(rows.map((row) => [row.tool, row.used]))
      const limit = limitFor(req.user, env)
      const unlimited = limit === Infinity

      const tools = Object.values(ToolName).map((tool) => {
        const used = usedByTool.get(tool) ?? 0
        return {
          tool,
          used,
          limit: unlimited ? null : limit,
          remaining: unlimited ? null : Math.max(limit - used, 0),
        }
      })

      res.set('Cache-Control', NO_STORE).json({
        date: utcDate(now),
        resetsAt: nextResetAt(now),
        tiers: { tier: req.user.tier },
        tools,
      })
    })
  )

  return router
}
