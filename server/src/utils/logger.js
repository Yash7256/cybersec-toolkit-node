import pino from 'pino'

const REDACTION_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  '*.password',
  '*.token',
  '*.secret',
]

export function createLogger(env) {
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

  return pino(options)
}
