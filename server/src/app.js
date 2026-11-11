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
import { createLimiter } from './middleware/rateLimit.js'

export function createApp({
  env = defaultEnv,
  logger = createLogger(env),
  auth,
  clerkClient,
  routes,
  webhooks,
  extraRoutes,
} = {}) {
  const resolvedAuth = auth ?? createAuth(env)
  const resolvedRoutes = routes ?? apiRouter({ auth: resolvedAuth, clerkClient, env })
  const resolvedWebhooks = webhooks ?? webhookRouter({ env, logger })

  const webhooksLimiter = createLimiter({
    name: 'webhooks_ip',
    points: 300,
    durationSec: 60,
    logger,
  })
  const globalLimiter = createLimiter({
    name: 'global_ip',
    points: env.RATE_LIMIT_MAX,
    durationSec: Math.max(1, Math.ceil(env.RATE_LIMIT_WINDOW_MS / 1000)),
    logger,
  })

  const app = express()

  app.disable('x-powered-by')
  app.set('trust proxy', env.TRUST_PROXY)

  app.use(requestId())

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
  app.use('/api/webhooks', webhooksLimiter)
  app.use(
    '/api/webhooks',
    express.raw({ type: 'application/json', limit: '1mb' }),
    resolvedWebhooks,
  )

  app.use(express.json({ limit: env.BODY_LIMIT }))

  app.use('/api', globalLimiter)

  app.use('/api', resolvedAuth.middleware)

  app.use('/api', resolvedRoutes)

  if (extraRoutes) {
    app.use('/api', extraRoutes)
  }

  app.use(notFound())

  app.use(errorHandler(logger, { isProduction: env.NODE_ENV === 'production' }))

  return app
}
