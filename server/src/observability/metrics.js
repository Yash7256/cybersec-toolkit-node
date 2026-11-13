import {
  Registry,
  collectDefaultMetrics,
  Counter,
  Gauge,
  Histogram,
} from 'prom-client'
import { pool } from '../db/client.js'

const BLOCK_REASONS = new Set([
  'loopback',
  'private',
  'link_local',
  'cgnat',
  'metadata',
  'multicast',
  'reserved',
  'documentation',
  'unspecified',
  'translation',
  'malformed',
])

const LIMITERS = new Set([
  'global_ip',
  'user_general',
  'submit_user',
  'submit_ip',
  'auth_fail',
  'webhooks_ip',
  'metrics',
  'target',
  'abuse',
])

const TOOLS = new Set([
  'PORT_SCAN',
  'WEBAPP_SCAN',
  'DNS',
  'WHOIS',
  'PING',
  'TRACEROUTE',
  'SSL',
  'HTTP_HEADERS',
  'SUBDOMAIN',
  'GEOIP',
])

const WEBHOOK_OUTCOMES = new Set(['processed', 'duplicate', 'failed', 'ignored'])
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
const STATUS_CLASSES = new Set(['2xx', '3xx', '4xx', '5xx'])
const ROUTE_PATTERN = /^\/[A-Za-z0-9_\-/:.]*$/

const allow = (allowed, value) => (allowed.has(value) ? value : 'other')

function safeRoute(route) {
  if (typeof route !== 'string' || route.length > 100 || !ROUTE_PATTERN.test(route)) {
    return 'unmatched'
  }
  return route
}

export function createMetrics() {
  const register = new Registry()
  collectDefaultMetrics({ register, prefix: 'cst_' })

  const policyBlocked = new Counter({
    name: 'cst_policy_blocked_total',
    help: 'Scan targets rejected by the target policy',
    labelNames: ['reason'],
    registers: [register],
  })

  const rateLimitRejected = new Counter({
    name: 'cst_rate_limit_rejected_total',
    help: 'Requests rejected by a rate limiter',
    labelNames: ['limiter'],
    registers: [register],
  })

  const rateLimitStoreErrors = new Counter({
    name: 'cst_rate_limit_store_errors_total',
    help: 'Rate limiter store failures that were failed open',
    labelNames: ['limiter'],
    registers: [register],
  })
  const legacyRateLimitStoreErrors = new Counter({
    name: 'rate_limit_store_errors_total',
    help: 'Deprecated alias for cst_rate_limit_store_errors_total',
    labelNames: ['limiter'],
    registers: [register],
  })

  const quotaRejected = new Counter({
    name: 'cst_quota_rejected_total',
    help: 'Requests rejected because the daily quota was exhausted',
    labelNames: ['tool'],
    registers: [register],
  })

  const webhookEvents = new Counter({
    name: 'cst_webhook_events_total',
    help: 'Clerk webhook events by outcome',
    labelNames: ['outcome'],
    registers: [register],
  })

  const httpRequestDuration = new Histogram({
    name: 'cst_http_request_duration_seconds',
    help: 'HTTP request duration in seconds',
    labelNames: ['method', 'route', 'status_class'],
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    registers: [register],
  })

  const dbPoolTotal = new Gauge({
    name: 'cst_db_pool_total',
    help: 'PostgreSQL pool connections',
    registers: [register],
    collect() { this.set(pool.totalCount) },
  })

  const dbPoolIdle = new Gauge({
    name: 'cst_db_pool_idle',
    help: 'PostgreSQL pool idle connections',
    registers: [register],
    collect() { this.set(pool.idleCount) },
  })

  const dbPoolWaiting = new Gauge({
    name: 'cst_db_pool_waiting',
    help: 'PostgreSQL pool waiting clients',
    registers: [register],
    collect() { this.set(pool.waitingCount) },
  })

  const eventLoopLagP99 = new Gauge({
    name: 'cst_eventloop_lag_p99_seconds',
    help: 'Event loop delay p99 in seconds',
    registers: [register],
  })

  const scanSocketsInUse = new Gauge({
    name: 'cst_scan_sockets_in_use',
    help: 'Scanner sockets currently held across all scans in this process',
    registers: [register],
  })

  const toolRuns = new Counter({
    name: 'cst_tool_runs_total',
    help: 'Tool runs by outcome',
    labelNames: ['tool', 'outcome'],
    registers: [register],
  })
  const toolDuration = new Histogram({
    name: 'cst_tool_run_duration_seconds',
    help: 'Tool run duration in seconds',
    labelNames: ['tool'],
    registers: [register],
  })
  const runsActive = new Gauge({
    name: 'cst_runs_active',
    help: 'Runs by status',
    labelNames: ['status'],
    registers: [register],
  })
  const runStatuses = new Set(['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT'])

  const breakerOpen = new Counter({
    name: 'cst_breaker_open_total',
    help: 'Upstream circuit breaker openings',
    labelNames: ['name'],
    registers: [register],
  })
  const toolNames = new Set(['dns', 'ssl', 'http_headers', 'whois', 'geoip', 'ping', 'port_scan'])
  const outcomes = new Set(['success', 'target', 'upstream', 'internal', 'timeout'])

  return {
    register,

    recordBlocked(reason) {
      policyBlocked.inc({ reason: allow(BLOCK_REASONS, reason) })
    },

    recordRateLimitRejected(limiter) {
      rateLimitRejected.inc({ limiter: allow(LIMITERS, limiter) })
    },

    recordRateLimitStoreError(limiter) {
      const value = allow(LIMITERS, limiter)
      rateLimitStoreErrors.inc({ limiter: value })
      legacyRateLimitStoreErrors.inc({ limiter: value })
    },

    recordQuotaRejected(tool) {
      quotaRejected.inc({ tool: allow(TOOLS, tool) })
    },

    recordWebhookEvent(outcome) {
      webhookEvents.inc({ outcome: allow(WEBHOOK_OUTCOMES, outcome) })
    },

    observeHttp({ method, route, status, durationSec }) {
      const upper = String(method ?? '').toUpperCase()
      const statusClass = `${Math.floor(Number(status) / 100)}xx`
      httpRequestDuration.observe(
        {
          method: allow(METHODS, upper),
          route: safeRoute(route),
          status_class: allow(STATUS_CLASSES, statusClass),
        },
        durationSec
      )
    },

    setDbPool({ total, idle, waiting }) {
      dbPoolTotal.set(total)
      dbPoolIdle.set(idle)
      dbPoolWaiting.set(waiting)
    },

    setEventLoopLag(seconds) {
      eventLoopLagP99.set(seconds)
    },

    setScanSocketsInUse(count) {
      scanSocketsInUse.set(Number(count) || 0)
    },

    recordToolRun(tool, outcome) {
      toolRuns.inc({ tool: toolNames.has(tool) ? tool : 'other', outcome: outcomes.has(outcome) ? outcome : 'other' })
    },

    observeToolRun(tool, seconds) {
      toolDuration.observe({ tool: toolNames.has(tool) ? tool : 'other' }, seconds)
    },

    setRunsActive(status, count) {
      runsActive.set({ status: runStatuses.has(status) ? status : 'other' }, Number(count) || 0)
    },

    recordBreakerOpen(name) {
      const allowed = new Set(['doh', 'rdap', 'geoip', 'whois43', 'nvd', 'intel'])
      breakerOpen.inc({ name: allowed.has(name) ? name : 'other' })
    },
  }
}

export const metrics = createMetrics()
