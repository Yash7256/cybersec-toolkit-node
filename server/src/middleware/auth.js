import { clerkMiddleware, getAuth } from '@clerk/express'
import AppError from '../utils/AppError.js'

export function clerkAuth(env) {
  return clerkMiddleware({
    publishableKey: env.CLERK_PUBLISHABLE_KEY,
    secretKey: env.CLERK_SECRET_KEY,
    authorizedParties: env.CORS_ORIGINS,
  })
}

export function requireAuth(req, _res, next) {
  const { userId, sessionId } = getAuth(req)
  if (!userId) {
    next(AppError.unauthorized('Authentication required'))
    return
  }
  req.auth = { clerkUserId: userId, sessionId }
  next()
}

export function createAuth(env) {
  return { middleware: clerkAuth(env), requireAuth }
}
