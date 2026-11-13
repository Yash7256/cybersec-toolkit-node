import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import { pinoHttp } from 'pino-http'
import { env as defaultEnv } from './config/env.js'
import { createLogger } from './utils/logger.js'
import requestId from './middleware/requestId.js'
import notFound from './middleware/notFound.js'
import errorHandler from './middleware/errorHandler.js'
import apiRouter from './routes/index.js'
import webhookRouter from './routes/webhooks.js'
import { createAuth } from './middleware/auth.js'
import { createLimiters } from './middleware/limiters.js'
import httpMetrics from './observability/httpMetrics.js'
import metricsRouter from './routes/metrics.js'

export function createApp({
  env = defaultEnv,
  logger = createLogger(env),
  auth,
  clerkClient,
  routes,
  webhooks,
  extraRoutes,
} = {}) {
  const limiters = createLimiters({ env, logger })
  const baseAuth = auth ?? createAuth(env)
  const resolvedAuth = {
    ...baseAuth,
    requireAuth(req, res, next) {
      baseAuth.requireAuth(req, res, (err) => {
        if (err && err.statusCode === 401) {
          limiters.authFail.penalize(req).then(() => next(err))
          return
        }
        next(err)
      })
    },
  }
  const resolvedRoutes =
    routes ?? apiRouter({ auth: resolvedAuth, clerkClient, env, limiters })
  const resolvedWebhooks = webhooks ?? webhookRouter({ env, logger })

  const app = express()

  app.disable('x-powered-by')
  app.set('trust proxy', env.TRUST_PROXY)

  app.use(requestId())
  app.use(httpMetrics())

  app.use(
    pinoHttp({
      logger,
      genReqId: (req) => req.id,
      autoLogging: { ignore: (req) => req.url === '/api/health' },
    }),
  )

  app.use(helmet())

  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin || env.CORS_ORIGINS.includes(origin)) {
          callback(null, true)
        } else {
          callback(null, false)
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      maxAge: 600,
    }),
  )

  // Webhooks need the exact raw bytes for signature verification, so they are
  // mounted before express.json() and before auth. They get their own limiter.
  app.use('/api/webhooks', limiters.webhooksIp)
  app.use(
    '/api/webhooks',
    express.raw({ type: 'application/json', limit: '1mb' }),
    resolvedWebhooks,
  )

  app.use(express.json({ limit: env.BODY_LIMIT }))

  app.use('/metrics', limiters.metrics, metricsRouter({ env }))

  app.use('/api', limiters.globalIp)

  // Reject blocked IPs before Clerk verification so failed attempts cost no
  // upstream work.
  app.use('/api', limiters.authFail.check)

  app.use('/api', resolvedAuth.middleware)

  app.use('/api', resolvedRoutes)

  if (extraRoutes) {
    app.use('/api', extraRoutes)
  }

  app.use(notFound())

  app.use(errorHandler(logger, { isProduction: env.NODE_ENV === 'production' }))

  return app
}
