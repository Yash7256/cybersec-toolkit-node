import { Router } from 'express'
import healthRouter from './health.js'
import userRouter from './user.js'

export default function apiRouter({ auth, clerkClient, env, limiters } = {}) {
  const router = Router()
  router.use('/', healthRouter())
  router.use('/user', userRouter({ auth, clerkClient, env, limiters }))
  return router
}
