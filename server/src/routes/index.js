import { Router } from 'express'
import healthRouter from './health.js'
import userRouter from './user.js'

export default function apiRouter({ auth, clerkClient, env } = {}) {
  const router = Router()
  router.use('/', healthRouter())
  router.use('/user', userRouter({ auth, clerkClient, env }))
  return router
}
