import { Router } from 'express'
import healthRouter from './health.js'

export default function apiRouter() {
  const router = Router()
  router.use('/', healthRouter())
  return router
}
