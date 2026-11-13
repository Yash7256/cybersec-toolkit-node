import { EventEmitter } from 'node:events'
import { describe, it, expect, vi } from 'vitest'
import { RESULT_KEYS, createTracerouteDefinition } from '../../src/tools/traceroute/index.js'
import { schema } from '../../src/tools/traceroute/schema.js'
import { parseTracerouteOutput } from '../../src/tools/traceroute/parser.js'
import { runTraceroute } from '../../src/tools/traceroute/runner.js'
import {
  emptyHop, qualityForLatency, detectProvider, createEnricher, isPrivateIp,
} from '../../src/tools/traceroute/enrich.js'
import { buildRouteIntelligence } from '../../src/tools/traceroute/intelligence.js'
import { ToolError } from '../../src/tools/_shared/errors.js'

const env = {
  TRACEROUTE_TIMEOUT_MS: 5000,
  TRACEROUTE_MAX_HOPS: 30,
  TRACEROUTE_BINARY: 'traceroute',
}

function hop(overrides = {}) {
  return {
    hop: 1, ip: null, hostname: null, rtt_ms: null, rtt_samples_ms: [],
    packet_loss_pct: 100, latency_added_ms: null, is_hidden: true,
    is_private: false, provider: null, asn: null, hop_type: 'Filtered Hop',
    country_code: null, cdn_provider: null, is_cdn: false, insight: null,
    ...overrides,
  }
}

describe('traceroute schema', () => {
  it('defaults and clamps max hops through validation', () => {
    expect(schema.parse({ target: ' example.com ' })).toEqual({ target: 'example.com', max_hops: 30 })
    expect(schema.parse({ target: 'example.com', max_hops: '5' }).max_hops).toBe(5)
    expect(() => schema.parse({ target: 'example.com', max_hops: 0 })).toThrow()
    expect(() => schema.parse({ target: 'example.com', max_hops: 65 })).toThrow()
  })
})

describe('traceroute parser', () => {
  it('parses visible, filtered and partial hop lines', () => {
    const output = [
      'traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets',
      ' 1  192.168.1.1  1.234 ms  2.000 ms  3.000 ms',
      ' 2  * * *',
      ' 3  8.8.8.8  10.500 ms * 11.000 ms',
    ].join('\n')
    const result = parseTracerouteOutput(output)
    expect(result.destinationIp).toBe('8.8.8.8')
    expect(result.rawHops).toEqual([
      { hop: 1, ip: '192.168.1.1', samples: [1.234, 2, 3] },
      { hop: 2, ip: null, samples: [] },
      { hop: 3, ip: '8.8.8.8', samples: [10.5, 11] },
    ])
  })

  it('ignores headers and malformed lines', () => {
    expect(parseTracerouteOutput('garbage\n 1 * * *\n 2 invalid')).toEqual({
      rawHops: [{ hop: 1, ip: null, samples: [] }],
      destinationIp: null,
    })
  })
})

describe('traceroute runner', () => {
  function fakeSpawn() {
    const child = new EventEmitter()
    child.stdout = new EventEmitter()
    child.stderr = new EventEmitter()
    child.kill = vi.fn(() => child.emit('close', null))
    return child
  }

  it('spawns traceroute with bounded arguments and collects stdout', async () => {
    const child = fakeSpawn()
    const spawnImpl = vi.fn(() => child)
    const pending = runTraceroute({ ip: '8.8.8.8', maxHops: 5, spawnImpl })
    child.stdout.emit('data', Buffer.from(' 1  8.8.8.8  1.0 ms\n'))
    child.emit('close', 0)
    await expect(pending).resolves.toMatchObject({ stdout: ' 1  8.8.8.8  1.0 ms\n', timedOut: false })
    expect(spawnImpl).toHaveBeenCalledWith('traceroute', ['-m', '5', '-n', '--', '8.8.8.8'], expect.any(Object))
  })

  it('rejects when the binary is unavailable', async () => {
    const child = fakeSpawn()
    const pending = runTraceroute({ ip: '8.8.8.8', spawnImpl: () => child })
    child.emit('error', new Error('ENOENT'))
    await expect(pending).rejects.toMatchObject({ kind: 'upstream' })
  })

  it('kills on abort', async () => {
    const child = fakeSpawn()
    const controller = new AbortController()
    const pending = runTraceroute({ ip: '8.8.8.8', spawnImpl: () => child, signal: controller.signal })
    controller.abort()
    expect(child.kill).toHaveBeenCalledWith('SIGKILL')
    await expect(pending).rejects.toMatchObject({ kind: 'cancelled' })
  })
})

describe('traceroute enrichment', () => {
  it('maps latency to legacy quality bands', () => {
    expect(qualityForLatency(null)).toEqual({ quality: 'Filtered', color: 'gray' })
    expect(qualityForLatency(10)).toEqual({ quality: 'Excellent', color: 'green' })
    expect(qualityForLatency(40)).toEqual({ quality: 'Good', color: 'cyan' })
    expect(qualityForLatency(100)).toEqual({ quality: 'Moderate', color: 'yellow' })
    expect(qualityForLatency(100.1)).toEqual({ quality: 'Poor', color: 'red' })
  })

  it('detects private, CDN and ISP hops', () => {
    expect(isPrivateIp('10.0.0.1')).toBe(true)
    expect(isPrivateIp('8.8.8.8')).toBe(false)
    expect(detectProvider('1.1.1.1', 'one.one.one.one')).toMatchObject({ isCdn: false })
    expect(detectProvider('104.16.0.1', 'cloudflare.com')).toMatchObject({
      provider: 'Cloudflare', cdnProvider: 'Cloudflare', isCdn: true, hopType: 'CDN Edge',
    })
    expect(detectProvider('10.0.0.1', null)).toMatchObject({ provider: 'Private network', hopType: 'Residential Router' })
    expect(detectProvider('8.8.8.8', 'edge.example.net')).toMatchObject({ provider: 'Example', hopType: 'ISP Backbone' })
  })

  it('computes sample loss, latency delta and CDN insight', async () => {
    const enricher = createEnricher({
      reverse: async () => 'edge.cloudflare.com',
      geoip: async () => ({}),
    })
    const enriched = await enricher.enrichHop(2, '104.16.0.1', [40.123, 50], 20)
    expect(enriched).toMatchObject({
      hop: 2, ip: '104.16.0.1', hostname: 'edge.cloudflare.com',
      rtt_ms: 45.061, rtt_samples_ms: [40.123, 50], packet_loss_pct: 33.3,
      latency_added_ms: 25.061, quality: 'Moderate', quality_color: 'yellow',
      provider: 'Cloudflare', cdn_provider: 'Cloudflare', is_cdn: true, hop_type: 'CDN Edge',
      insight: "Hop 2 dropped 33% of traceroute probes.",
    })
  })

  it('applies geoip only to the first 16 public visible hops', async () => {
    const calls = []
    const enricher = createEnricher({
      reverse: async () => null,
      geoip: async (ip) => { calls.push(ip); return { country: 'US', country_code: 'US', lat: 1, lon: 2 } },
    })
    const hops = Array.from({ length: 20 }, (_, index) => hop({
      hop: index + 1, ip: `8.8.8.${index + 1}`, is_hidden: false, is_private: false, rtt_ms: 1,
    }))
    await enricher.applyGeoip(hops)
    expect(calls).toHaveLength(16)
    expect(hops[0]).toMatchObject({ country: 'US', country_code: 'US', lat: 1, lon: 2 })
    expect(hops[19].country).toBeUndefined()
  })
})

describe('traceroute intelligence', () => {
  it('scores bottlenecks, hidden hops and cross-border routes', () => {
    const hops = [
      hop({ hop: 1, ip: '192.168.1.1', rtt_ms: 1, packet_loss_pct: 0, is_hidden: false, latency_added_ms: null, is_private: true }),
      hop({ hop: 2, ip: '8.8.8.8', rtt_ms: 50, packet_loss_pct: 0, is_hidden: false, latency_added_ms: 48, country_code: 'US' }),
      hop({ hop: 3 }),
      hop({ hop: 4, ip: '1.1.1.1', rtt_ms: 20, packet_loss_pct: 0, is_hidden: false, latency_added_ms: -30, country_code: 'AU' }),
    ]
    const result = buildRouteIntelligence('example.com', hops, '1.1.1.1')
    expect(result.destination_ip).toBe('1.1.1.1')
    expect(result.hidden_hops).toBe(1)
    expect(result.packet_loss_hops).toBe(1)
    expect(result.bottlenecks).toHaveLength(1)
    expect(result.bottlenecks[0].hop).toBe(2)
    expect(result.international_route).toBe(true)
    expect(result.route_stability_score).toBeGreaterThanOrEqual(0)
    expect(result.route_stability_score).toBeLessThanOrEqual(100)
    expect(result.health_indicators).toContain('CONGESTION SIGNAL')
    expect(result.route_risk).toBe('High')
    expect(result.route_risk_factors).toEqual(expect.arrayContaining([
      'Filtered intermediate routers reduce route visibility.',
      'A large latency jump indicates congestion or long-distance transit.',
      'Traffic crosses multiple geographic regions.',
    ]))
    expect(result.ai_summary).toContain('Traceroute to example.com reached 3 visible hop(s)')
  })

  it('reports a healthy direct route', () => {
    const result = buildRouteIntelligence('example.com', [
      hop({ hop: 1, ip: '8.8.8.8', rtt_ms: 5, packet_loss_pct: 0, is_hidden: false }),
    ], '8.8.8.8')
    expect(result).toMatchObject({
      route_stability_score: 100, route_efficiency: 'Excellent', route_risk: 'Low',
      hidden_hops: 0, packet_loss_hops: 0, international_route: false,
    })
    expect(result.routing_intelligence).toEqual(['Route appears direct with no major inferred transit anomaly.'])
    expect(result.security_insights).toEqual(['No obvious traceroute security anomaly detected.'])
  })
})

describe('traceroute orchestrator', () => {
  const enricher = {
    enrichHop: async (hopNumber, ip, samples, previousRtt) => hop({
      hop: hopNumber, ip, rtt_ms: samples[0] ?? null, packet_loss_pct: 0, is_hidden: false,
      latency_added_ms: previousRtt == null ? null : samples[0] - previousRtt,
    }),
    applyGeoip: async (hops) => hops,
  }

  it('returns the legacy shape and passes the validated address', async () => {
    const runner = vi.fn(async ({ ip, maxHops }) => ({
      stdout: ` 1  ${ip}  5.0 ms  5.0 ms  5.0 ms\n`, timedOut: false,
    }))
    const definition = createTracerouteDefinition({ env, runner, enricher })
    const result = await definition.execute(
      definition.normalize({ target: 'example.com', max_hops: 3 }),
      { env, target: { addresses: [{ address: '93.184.216.34', family: 4 }] } }
    )
    expect(runner).toHaveBeenCalledWith(expect.objectContaining({ ip: '93.184.216.34', maxHops: 3 }))
    expect(Object.keys(result).sort()).toEqual([...RESULT_KEYS].sort())
    expect(result.total_hops).toBe(1)
    expect(result.hops[0]).toMatchObject({ ip: '93.184.216.34', rtt_ms: 5 })
    expect(result.destination_ip).toBe('93.184.216.34')
    expect(definition.summarize(result)).toMatchObject({ total_hops: 1, destination_ip: '93.184.216.34' })
  })

  it('returns a bounded timeout result', async () => {
    const definition = createTracerouteDefinition({
      env: { ...env, TRACEROUTE_TIMEOUT_MS: 1500 },
      runner: async () => ({ stdout: '', timedOut: true }),
      enricher,
    })
    const result = await definition.execute(
      definition.normalize({ target: 'example.com' }),
      { env: { ...env, TRACEROUTE_TIMEOUT_MS: 1500 }, target: { addresses: [{ address: '8.8.8.8', family: 4 }] } }
    )
    expect(result.hops).toEqual([])
    expect(result.error).toBe('Traceroute timed out after 2s')
  })

  it('requires a validated target address', async () => {
    const definition = createTracerouteDefinition({ env, runner: async () => ({ stdout: '' }), enricher })
    await expect(definition.execute(definition.normalize({ target: 'example.com' }), { env }))
      .rejects.toMatchObject({ kind: 'target' })
  })

  it('turns runner failures into an error result', async () => {
    const definition = createTracerouteDefinition({
      env,
      runner: async () => { throw new ToolError('upstream', 'Traceroute unavailable') },
      enricher,
    })
    const result = await definition.execute(
      definition.normalize({ target: 'example.com' }),
      { env, target: { addresses: [{ address: '8.8.8.8', family: 4 }] } }
    )
    expect(result.error).toBe('Traceroute unavailable')
    expect(result.total_hops).toBe(0)
  })
})
