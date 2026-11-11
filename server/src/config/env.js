import 'dotenv/config'
import { z } from 'zod'

const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']

const isUrlOrigin = (value) => {
  try {
    const url = new URL(value)
    return (
      Boolean(url.origin && url.origin !== 'null') &&
      (url.pathname === '' || url.pathname === '/') &&
      url.search === '' &&
      url.hash === ''
    )
  } catch {
    return false
  }
}

const corsOrigins = z
  .string()
  .default('http://localhost:5173')
  .transform((value) => value.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0))
  .pipe(z.array(z.string().refine(isUrlOrigin, { message: 'must be a valid URL origin' })).min(1))

const pgConnectionString = z
  .string()
  .min(1)
  .refine((value) => value.startsWith('postgres://') || value.startsWith('postgresql://'), {
    message: 'must start with postgres:// or postgresql://',
  })

const prefixedString = (prefix) =>
  z.string().refine((value) => value.startsWith(prefix), {
    message: `must start with ${prefix}`,
  })

// Empty string in .env means "not configured" until T3.21 sets a real secret.
const optionalWebhookSecret = z.preprocess(
  (value) => (value === '' ? undefined : value),
  prefixedString('whsec_').optional()
)

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
  CORS_ORIGINS: corsOrigins,
  TRUST_PROXY: z.coerce.number().int().min(0).default(0),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).default(60000),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),
  BODY_LIMIT: z.string().default('100kb'),
  DATABASE_URL: pgConnectionString,
  DIRECT_URL: pgConnectionString,
  DB_POOL_MAX: z.coerce.number().int().min(1).default(10),
  DB_STATEMENT_TIMEOUT_MS: z.coerce.number().int().min(0).default(10000),
  DB_IDLE_TX_TIMEOUT_MS: z.coerce.number().int().min(0).default(15000),
  CLERK_PUBLISHABLE_KEY: prefixedString('pk_'),
  CLERK_SECRET_KEY: prefixedString('sk_'),
  CLERK_WEBHOOK_SIGNING_SECRET: optionalWebhookSecret,
  FREE_DAILY_LIMIT: z.coerce.number().int().min(1).default(5),
  PAID_DAILY_LIMIT: z.coerce.number().int().min(1).default(100),
}).superRefine((data, ctx) => {
  if (data.NODE_ENV === 'production' && !data.CLERK_WEBHOOK_SIGNING_SECRET) {
    ctx.addIssue({
      code: 'custom',
      path: ['CLERK_WEBHOOK_SIGNING_SECRET'],
      message: 'is required in production',
    })
  }
})

export function parseEnv(raw = process.env) {
  const result = EnvSchema.safeParse(raw)
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n')
    throw new Error(`Invalid environment variables:\n${issues}`)
  }
  return Object.freeze(result.data)
}

export const env = (() => {
  try {
    return parseEnv()
  } catch (e) {
    if (process.env.NODE_ENV === 'test') throw e
    console.error(e.message)
    process.exit(1)
  }
})()
