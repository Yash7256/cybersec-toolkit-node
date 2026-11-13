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

const redisConnectionString = z.string().refine(
  (value) => value.startsWith('redis://') || value.startsWith('rediss://'),
  { message: 'must start with redis:// or rediss://' }
)

// Never z.coerce.boolean(): it turns the string "false" into true.
const envBoolean = z.preprocess(
  (value) => (typeof value === 'boolean' ? (value ? 'true' : 'false') : value),
  z
    .enum(['true', 'false'])
    .default('false')
    .transform((value) => value === 'true')
)

const optionalToken = z.preprocess(
  (value) => (value === '' ? undefined : value),
  z.string().min(24, { message: 'must be at least 24 characters' }).optional()
)

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
  REDIS_URL: redisConnectionString,
  DB_POOL_MAX: z.coerce.number().int().min(1).default(10),
  DB_STATEMENT_TIMEOUT_MS: z.coerce.number().int().min(0).default(10000),
  DB_IDLE_TX_TIMEOUT_MS: z.coerce.number().int().min(0).default(15000),
  CLERK_PUBLISHABLE_KEY: prefixedString('pk_'),
  CLERK_SECRET_KEY: prefixedString('sk_'),
  CLERK_WEBHOOK_SIGNING_SECRET: optionalWebhookSecret,
  FREE_DAILY_LIMIT: z.coerce.number().int().min(1).default(5),
  PAID_DAILY_LIMIT: z.coerce.number().int().min(1).default(100),
  ALLOW_PRIVATE_TARGETS: envBoolean,
  METRICS_TOKEN: optionalToken,
  DNS_TIMEOUT_MS: z.coerce.number().int().min(100).default(3000),
  USER_RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(300),
  SUBMIT_RATE_LIMIT_USER: z.coerce.number().int().min(1).default(10),
  SUBMIT_RATE_LIMIT_IP: z.coerce.number().int().min(1).default(30),
  AUTH_FAIL_MAX: z.coerce.number().int().min(1).default(20),
  AUTH_FAIL_WINDOW_SEC: z.coerce.number().int().min(1).default(600),
  AUTH_FAIL_BLOCK_SEC: z.coerce.number().int().min(1).default(900),
  TARGET_HOURLY_LIMIT_GLOBAL: z.coerce.number().int().min(1).default(20),
  TARGET_HOURLY_LIMIT_USER: z.coerce.number().int().min(1).default(5),
  BLOCKED_ATTEMPTS_MAX: z.coerce.number().int().min(1).default(5),
  BLOCKED_ATTEMPTS_WINDOW_SEC: z.coerce.number().int().min(1).default(600),
  BLOCKED_COOLDOWN_SEC: z.coerce.number().int().min(1).default(900),
  HTTP_USER_AGENT: z.string().min(1).default('CyberSecToolkit/1.0'),
  TOOL_HARD_TIMEOUT_MS: z.coerce.number().int().min(100).default(30000),
  MAX_CONCURRENT_TOOL_RUNS: z.coerce.number().int().min(1).default(50),
  SSL_AUDIT_TIMEOUT_MS: z.coerce.number().int().min(100).default(20000),
  WHOIS_TIMEOUT_MS: z.coerce.number().int().min(100).default(8000),
  WHOIS_CACHE_TTL_SEC: z.coerce.number().int().min(1).default(3600),
  WHOIS_PRIVACY_PATTERNS: z.string().default('privacy,redacted,whoisguard,domains by proxy,contact privacy,data protected,private registration,withheld'),
  WHOIS_SUSPICIOUS_STATUS_TOKENS: z.string().default('hold,pendingdelete,redemptionperiod,serverdeleteprohibited,clienthold'),
  GEOIP_PROVIDER_ORDER: z.string().default('ipinfo,ipwhois'),
  IPINFO_API_TOKEN: optionalToken,
  GEOIP_TIMEOUT_MS: z.coerce.number().int().min(100).default(5000),
  GEOIP_CACHE_TTL_SEC: z.coerce.number().int().min(1).default(3600),
  GEOIP_RATE_PER_MIN: z.coerce.number().int().min(1).default(55),
  GEOIP_MAX_CONCURRENT: z.coerce.number().int().min(1).default(5),
  GEOIP_ALLOW_INSECURE_PROVIDER: envBoolean,
  PING_METHOD: z.enum(['auto', 'icmp', 'tcp']).default('auto'),
  PING_HISTORY_TTL_SEC: z.coerce.number().int().min(1).default(3600),
  SCAN_MAX_CONCURRENCY: z.coerce.number().int().min(1).default(200),
  SCAN_DEFAULT_CONCURRENCY: z.coerce.number().int().min(1).default(100),
  SCAN_RATE_CONN_PER_SEC: z.coerce.number().int().min(1).default(300),
  SCAN_GLOBAL_MAX_SOCKETS: z.coerce.number().int().min(1).default(1500),
  SCAN_TIMEOUT_MS: z.coerce.number().int().min(100).default(300000),
  SUBDOMAIN_DNS_CONCURRENCY: z.coerce.number().int().min(1).max(100).default(20),
  SUBDOMAIN_HTTP_CONCURRENCY: z.coerce.number().int().min(1).max(50).default(10),
  SUBDOMAIN_HTTP_TIMEOUT_MS: z.coerce.number().int().min(100).default(5000),
  SUBDOMAIN_WILDCARD_CHECKS: z.coerce.number().int().min(1).max(10).default(3),
  TRACEROUTE_TIMEOUT_MS: z.coerce.number().int().min(1000).max(600000).default(60000),
  TRACEROUTE_MAX_HOPS: z.coerce.number().int().min(1).max(64).default(30),
  TRACEROUTE_BINARY: z.string().min(1).default('traceroute'),
  WEBAPP_SCAN_TIMEOUT_MS: z.coerce.number().int().min(1000).max(900000).default(120000),
  WEBAPP_REQUEST_TIMEOUT_MS: z.coerce.number().int().min(100).default(10000),
  WEBAPP_MAX_RESPONSE_BYTES: z.coerce.number().int().min(1024).max(5 * 1024 * 1024).default(512 * 1024),
  WEBAPP_CHECK_CONCURRENCY: z.coerce.number().int().min(1).max(50).default(8),
  WEBAPP_SCAN_MAX_PAGES: z.coerce.number().int().min(1).max(100).default(100),
  WEBAPP_SCAN_TOTAL_TIMEOUT_SEC: z.coerce.number().int().min(1).max(1800).default(180),
  WEBAPP_SCAN_USER_LIMIT_PER_DAY: z.coerce.number().int().min(1).default(10),
  WEBAPP_AUTH_ATTESTATION_COOLDOWN_SEC: z.coerce.number().int().min(1).default(60),
  NVD_API_KEY: z.preprocess((value) => (value === '' ? undefined : value), z.string().min(8).optional()),
  NVD_CACHE_TTL_HOURS: z.coerce.number().int().min(1).default(24),
  NVD_MAX_RESULTS_PER_SERVICE: z.coerce.number().int().min(1).default(10),
  NVD_MIN_CVSS_SCORE: z.coerce.number().min(0).max(10).default(5.0),
  ABUSEIPDB_API_KEY: z.preprocess((value) => (value === '' ? undefined : value), z.string().min(8).optional()),
  THREAT_INTEL_SPAMHAUS: envBoolean,
  THREAT_INTEL_CACHE_TTL_SEC: z.coerce.number().int().min(1).default(3600),
  QUEUE_PREFIX: z.string().regex(/^[A-Za-z0-9_-]{1,32}$/).default('cst'),
  WORKER_CONCURRENCY: z.coerce.number().int().min(1).default(10),
  WORKER_HEARTBEAT_SEC: z.coerce.number().int().min(1).default(15),
  RUN_STALL_SEC: z.coerce.number().int().min(4).default(120),
  RUN_MAX_ATTEMPTS: z.coerce.number().int().min(1).default(2),
  QUEUE_MAX_WAITING: z.coerce.number().int().min(1).default(1000),
  QUEUE_MAX_WAIT_SEC: z.coerce.number().int().min(1).default(900),
  ORPHAN_QUEUED_SEC: z.coerce.number().int().min(1).default(60),
  MAX_ACTIVE_RUNS_FREE: z.coerce.number().int().min(1).default(2),
  MAX_ACTIVE_RUNS_PAID: z.coerce.number().int().min(1).default(5),
  WORKER_SHUTDOWN_GRACE_MS: z.coerce.number().int().min(1000).default(25000),
  RUN_EMBEDDED_WORKER: envBoolean,
  WORKER_HEALTH_PORT: z.coerce.number().int().min(1).max(65535).default(3002),
  MAINTENANCE_ENABLED: envBoolean,
  RETENTION_DAYS_FREE: z.coerce.number().int().min(1).default(90),
  RETENTION_DAYS_PAID: z.coerce.number().int().min(1).default(365),
  RETENTION_USAGE_DAYS: z.coerce.number().int().min(1).default(400),
  RETENTION_WEBHOOK_DAYS: z.coerce.number().int().min(1).default(30),
  RETENTION_BATCH_SIZE: z.coerce.number().int().min(1).max(5000).default(5000),
  RETENTION_MAX_BATCHES: z.coerce.number().int().min(1).default(50),
  RETENTION_DRY_RUN: envBoolean,
}).superRefine((data, ctx) => {
  if (data.NODE_ENV === 'production' && !data.CLERK_WEBHOOK_SIGNING_SECRET) {
    ctx.addIssue({
      code: 'custom',
      path: ['CLERK_WEBHOOK_SIGNING_SECRET'],
      message: 'is required in production',
    })
  }
  if (data.NODE_ENV === 'production' && data.ALLOW_PRIVATE_TARGETS) {
    ctx.addIssue({
      code: 'custom',
      path: ['ALLOW_PRIVATE_TARGETS'],
      message: 'must be false in production',
    })
  }
  if (data.RUN_STALL_SEC < data.WORKER_HEARTBEAT_SEC * 4) {
    ctx.addIssue({ code: 'custom', path: ['RUN_STALL_SEC'], message: 'must be at least four times WORKER_HEARTBEAT_SEC' })
  }
  if (data.NODE_ENV === 'production' && data.RUN_EMBEDDED_WORKER) {
    ctx.addIssue({ code: 'custom', path: ['RUN_EMBEDDED_WORKER'], message: 'must be false in production' })
  }
})

export function parseEnv(raw = process.env) {
  const withPhase6Defaults = { ...raw }
  if (withPhase6Defaults.RUN_EMBEDDED_WORKER === undefined) withPhase6Defaults.RUN_EMBEDDED_WORKER = withPhase6Defaults.NODE_ENV === 'production' ? 'false' : 'true'
  if (withPhase6Defaults.MAINTENANCE_ENABLED === undefined) withPhase6Defaults.MAINTENANCE_ENABLED = 'true'
  const result = EnvSchema.safeParse(withPhase6Defaults)
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
