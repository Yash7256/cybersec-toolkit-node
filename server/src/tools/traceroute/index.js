import { env as defaultEnv } from '../../config/env.js'
import { ToolError } from '../_shared/errors.js'
import { schema, inputShape } from './schema.js'
import { runTraceroute } from './runner.js'
import { parseTracerouteOutput } from './parser.js'
import { emptyHop, createEnricher } from './enrich.js'
import { buildRouteIntelligence } from './intelligence.js'

export const RESULT_KEYS = Object.freeze([
  'target',
  'hops',
  'total_hops',
  'error',
  'destination_ip',
  'route_stability_score',
  'route_efficiency',
  'health_indicators',
  'autonomous_system_path',
  'ownership_chain',
  'bottlenecks',
  'hidden_hops',
  'packet_loss_hops',
  'international_route',
  'cdn_detected',
  'route_risk',
  'route_risk_factors',
  'routing_intelligence',
  'ai_summary',
  'security_insights',
])

export function emptyTracerouteResult(input = {}) {
  return {
    target: input.target ?? null,
    hops: [],
    total_hops: 0,
    error: null,
    destination_ip: null,
    route_stability_score: null,
    route_efficiency: null,
    health_indicators: null,
    autonomous_system_path: null,
    ownership_chain: null,
    bottlenecks: null,
    hidden_hops: 0,
    packet_loss_hops: 0,
    international_route: false,
    cdn_detected: null,
    route_risk: null,
    route_risk_factors: null,
    routing_intelligence: null,
    ai_summary: null,
    security_insights: null,
  }
}

export function createTracerouteDefinition({
  env = defaultEnv,
  runner = runTraceroute,
  enricher = null,
} = {}) {
  return {
    name: 'traceroute',
    toolEnum: 'TRACEROUTE',
    schema,
    inputShape,
    touchesTarget: true,
    mode: 'async',
    timeoutMs: env.TRACEROUTE_TIMEOUT_MS + 5000,
    dedupeTtlSec: 300,
    normalize(input) {
      return {
        ...input,
        target: input.target.trim(),
        max_hops: input.max_hops ?? env.TRACEROUTE_MAX_HOPS,
      }
    },
    emptyResult: emptyTracerouteResult,
    async execute(input, ctx = {}) {
      const runEnv = ctx.env ?? env
      const signal = ctx.signal
      const reportProgress = ctx.reportProgress ?? (() => {})
      const maxHops = Math.max(1, Math.min(64, input.max_hops ?? runEnv.TRACEROUTE_MAX_HOPS))
      const address = ctx.target?.addresses?.[0]

      if (!address) throw new ToolError('target', 'Target is not allowed')

      let output
      try {
        output = await runner({
          ip: address.address,
          maxHops,
          timeoutMs: runEnv.TRACEROUTE_TIMEOUT_MS,
          signal,
          binary: runEnv.TRACEROUTE_BINARY,
        })
      } catch (err) {
        if (err instanceof ToolError && err.kind === 'cancelled') throw err
        return {
          ...emptyTracerouteResult(input),
          error: err?.message || 'Traceroute failed',
        }
      }

      if (output.timedOut) {
        return {
          ...emptyTracerouteResult(input),
          error: `Traceroute timed out after ${Math.round(runEnv.TRACEROUTE_TIMEOUT_MS / 1000)}s`,
        }
      }

      reportProgress(35)
      const { rawHops, destinationIp } = parseTracerouteOutput(output.stdout)
      if (rawHops.length === 0) {
        return {
          ...emptyTracerouteResult(input),
          destination_ip: destinationIp,
        }
      }

      const previousRtts = []
      let previous = null
      for (const raw of rawHops) {
        previousRtts.push(previous)
        if (raw.ip != null && raw.samples.length > 0) {
          previous = Math.round((raw.samples.reduce((sum, value) => sum + value, 0) / raw.samples.length) * 1000) / 1000
        }
      }

      const enrich = enricher ?? createEnricher({ env: runEnv, signal })
      const hops = await Promise.all(rawHops.map((raw, index) => (
        raw.ip == null
          ? emptyHop(raw.hop)
          : enrich.enrichHop(raw.hop, raw.ip, raw.samples, previousRtts[index])
      )))

      reportProgress(70)
      await enrich.applyGeoip(hops)
      const intelligence = buildRouteIntelligence(input.target, hops, destinationIp)
      reportProgress(100)

      return {
        ...emptyTracerouteResult(input),
        target: input.target,
        hops,
        total_hops: hops.length,
        ...intelligence,
      }
    },
    summarize(data) {
      return {
        total_hops: data.total_hops ?? 0,
        destination_ip: data.destination_ip ?? null,
        route_stability_score: data.route_stability_score ?? null,
        route_risk: data.route_risk ?? null,
        cdn_detected: data.cdn_detected ?? null,
      }
    },
  }
}

export const definition = createTracerouteDefinition()
export { schema }
