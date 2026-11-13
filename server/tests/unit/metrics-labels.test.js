import { describe, it, expect } from 'vitest'
import { metrics } from '../../src/observability/metrics.js'

async function series(name, labelName) {
  const metric = metrics.register.getSingleMetric(name)
  const data = await metric.get()
  return [...new Set(data.values.map((value) => value.labels[labelName]))]
}

async function total(name) {
  const metric = metrics.register.getSingleMetric(name)
  const data = await metric.get()
  return data.values.reduce((sum, value) => sum + value.value, 0)
}

describe('metrics label cardinality', () => {
  it('collapses unknown enumerated label values to other', async () => {
    metrics.recordToolRun('not-a-tool', 'not-an-outcome')
    metrics.recordRateLimitRejected('not-a-limiter')
    metrics.recordBreakerOpen('not-a-breaker')
    metrics.recordQuotaRejected('NOT_A_TOOL')

    expect(await series('cst_tool_runs_total', 'tool')).toContain('other')
    expect(await series('cst_tool_runs_total', 'outcome')).toContain('other')
    expect(await series('cst_rate_limit_rejected_total', 'limiter')).toContain('other')
    expect(await series('cst_breaker_open_total', 'name')).toContain('other')
    expect(await series('cst_quota_rejected_total', 'tool')).toContain('other')
  })

  it('never records an unbounded route or method label', async () => {
    const before = await series('cst_http_request_duration_seconds', 'route')

    metrics.observeHttp({
      method: 'BREW',
      route: '/api/users/550e8400-e29b-41d4-a716-446655440000?secret=1',
      status: 200,
      durationSec: 0.001,
    })

    const after = await series('cst_http_request_duration_seconds', 'route')
    expect(after).toContain('unmatched')
    for (const route of after) {
      expect(route).not.toContain('?')
      expect(route).not.toContain('550e8400')
    }
    expect(after.length).toBeLessThanOrEqual(before.length + 1)
    expect(await series('cst_http_request_duration_seconds', 'method')).toContain('other')
  })

  it('records every known HTTP status class only', async () => {
    for (const status of [199, 200, 301, 404, 500, 999]) {
      metrics.observeHttp({ method: 'GET', route: '/api/health', status, durationSec: 0.001 })
    }
    const classes = await series('cst_http_request_duration_seconds', 'status_class')
    for (const value of classes) {
      expect(['2xx', '3xx', '4xx', '5xx', 'other']).toContain(value)
    }
  })

  it('counts policy blocks with a bounded reason label', async () => {
    const before = await total('cst_policy_blocked_total')
    metrics.recordBlocked('private')
    metrics.recordBlocked('a reason with spaces and 10.0.0.1')
    expect(await total('cst_policy_blocked_total')).toBe(before + 2)
    expect(await series('cst_policy_blocked_total', 'reason')).toContain('other')
  })
})
