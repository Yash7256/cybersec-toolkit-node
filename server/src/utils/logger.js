import pino from 'pino'

const loggerCache = new Map()

const REDACTION_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["svix-signature"]',
  'res.headers["set-cookie"]',
  '*.password',
  '*.token',
  '*.secret',
]

export function createLogger(env) {
  const cacheKey = `${env.NODE_ENV}:${env.LOG_LEVEL}`
  const cached = loggerCache.get(cacheKey)
  if (cached) return cached

  const options = {
    level: env.LOG_LEVEL,
    redact: { paths: REDACTION_PATHS, censor: '[redacted]' },
  }

  if (env.NODE_ENV === 'development') {
    options.transport = {
      target: 'pino-pretty',
      options: { colorize: true },
    }
  }

  const logger = pino(options)
  loggerCache.set(cacheKey, logger)
  return logger
}
