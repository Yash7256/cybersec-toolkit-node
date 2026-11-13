import { Router } from 'express'
import healthRouter from './health.js'
import userRouter from './user.js'
import toolsRouter from './tools.js'
import runsRouter from './runs.js'
import authorizationsRouter from './authorizations.js'

export default function apiRouter({ auth, clerkClient, env, limiters } = {}) {
  const router = Router()
  router.use('/', healthRouter())
  router.use('/user', userRouter({ auth, clerkClient, env, limiters }))
  router.use('/tools', toolsRouter({ auth, clerkClient, env, limiters }))
  router.use('/runs', runsRouter({ auth, clerkClient }))
  router.use('/authorizations', authorizationsRouter({ auth, clerkClient }))
  return router
}
