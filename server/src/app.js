import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { pinoHttp } from 'pino-http'
import { env as defaultEnv } from './config/env.js'
import { createLogger } from './utils/logger.js'
import requestId from './middleware/requestId.js'
import notFound from './middleware/notFound.js'
import errorHandler from './middleware/errorHandler.js'
import apiRouter from './routes/index.js'
import AppError from './utils/AppError.js'

export function createApp({ env = defaultEnv, logger = createLogger(env), routes = apiRouter() } = {}) {
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

  app.use(express.json({ limit: env.BODY_LIMIT }))

  app.use(
    '/api',
    rateLimit({
      windowMs: env.RATE_LIMIT_WINDOW_MS,
      limit: env.RATE_LIMIT_MAX,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      handler: (req, res, next) => {
        next(AppError.tooMany())
      },
    }),
  )

  app.use('/api', routes)

  app.use(notFound())

  app.use(errorHandler(logger, { isProduction: env.NODE_ENV === 'production' }))

  return app
}
