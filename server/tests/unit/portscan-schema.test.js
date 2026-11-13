import { describe, it, expect } from 'vitest'
import { schema } from '../../src/tools/portScan/schema.js'
import { OPEN_PORT_KEYS, PORT_SCAN_RESULT_KEYS } from '../../src/tools/portScan/contract.js'
import { createPortScanDefinition } from '../../src/tools/portScan/index.js'
import { COMMON_PORTS } from '../../src/scanner/data/portRegistry.js'

const target = 'example.com'

describe('port scan schema', () => {
  it('applies defaults and uses the common port list', async () => {
    const parsed = schema.parse({ target })
    expect(parsed).toMatchObject({
      timeout: 2,
      max_concurrent: 100,
      include_ai_recommendations: true,
      include_threat_intel: true,
      include_misconfigurations: true,
      include_screenshots: true,
      ports: null,
    })
    expect(parsed.start_port).toBeNull()
    expect(parsed.end_port).toBeNull()
  })

  it('accepts numeric lists, spec strings, and ranges', () => {
    expect(schema.parse({ target, ports: [22, 80, 443] }).ports).toEqual([22, 80, 443])
    expect(schema.parse({ target, ports: '22,80-82' }).ports).toEqual([22, 80, 81, 82])
    expect(schema.parse({ target, start_port: 20, end_port: 22 }).ports).toEqual([20, 21, 22])
    expect(schema.parse({ target, ports: [22, 22, 23] }).ports).toEqual([22, 23])
  })

  it('rejects conflicting, incomplete, reversed, and oversized inputs', () => {
    expect(schema.safeParse({ target, ports: [22], start_port: 1, end_port: 2 }).success).toBe(false)
    expect(schema.safeParse({ target, start_port: 1 }).success).toBe(false)
    expect(schema.safeParse({ target, end_port: 2 }).success).toBe(false)
    expect(schema.safeParse({ target, start_port: 5, end_port: 1 }).success).toBe(false)
    expect(schema.safeParse({ target, ports: [0] }).success).toBe(false)
    expect(schema.safeParse({ target, ports: [70000] }).success).toBe(false)
    expect(schema.safeParse({ target, ports: Array.from({ length: 1001 }, (_, i) => i + 1) }).success).toBe(false)
    expect(schema.safeParse({ target, start_port: 1, end_port: 6000 }).success).toBe(false)
  })

  it('publishes the full contract keys, including Phase 8 placeholders', () => {
    expect(OPEN_PORT_KEYS).toEqual(
      expect.arrayContaining(['screenshot', 'screenshot_url', 'recommendation', 'recommendation_reason', 'recommendation_priority'])
    )
    expect(PORT_SCAN_RESULT_KEYS).toEqual(
      expect.arrayContaining(['scanned_ip', 'closed_count', 'filtered_count', 'max_concurrent_effective', 'cve_error', 'intel_error'])
    )
    const empty = createPortScanDefinition({ env: { SCAN_TIMEOUT_MS: 1000 } }).emptyResult({ target })
    expect(Object.keys(empty).sort()).toEqual([...PORT_SCAN_RESULT_KEYS].sort())
  })

  it('defaults to every common port and clamps concurrency', async () => {
    const calls = []
    const definition = createPortScanDefinition({
      env: {
        SCAN_MAX_CONCURRENCY: 10,
        SCAN_DEFAULT_CONCURRENCY: 5,
        SCAN_RATE_CONN_PER_SEC: 10,
        SCAN_TIMEOUT_MS: 1000,
      },
      scanner: async (options) => {
        calls.push(options)
        return {
          open: [],
          total_scanned: options.ports.length,
          open_ports_count: 0,
          closed_count: 0,
          filtered_count: 0,
          packets_sent: options.ports.length,
          avg_latency_ms: null,
          scan_duration_seconds: 0.1,
          aborted: false,
        }
      },
      createDetector: () => ({ detectCvesBatch: async () => ({}), error: null }),
      misconfigDetector: async () => ({ total: 0, critical: 0, high: 0, medium: 0, low: 0, categories: [] }),
      intelCheck: async () => ({ reputation: 'Clean', error: null }),
    })
    const input = schema.parse({ target, max_concurrent: 500 })
    const result = await definition.execute(input, {
      target: { targetKey: 'example.com', addresses: [{ address: '93.184.216.34', family: 4 }] },
      env: {
        SCAN_MAX_CONCURRENCY: 10,
        SCAN_DEFAULT_CONCURRENCY: 5,
        SCAN_RATE_CONN_PER_SEC: 10,
        SCAN_TIMEOUT_MS: 1000,
      },
      reportProgress: () => {},
    })
    expect(calls[0].ports).toEqual(Object.keys(COMMON_PORTS).map(Number).sort((a, b) => a - b))
    expect(calls[0].concurrency).toBe(10)
    expect(result.max_concurrent_effective).toBe(10)
    expect(result.error).toBeNull()
  })
})
