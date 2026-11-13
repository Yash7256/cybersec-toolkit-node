import { existsSync } from 'node:fs'
import { z } from 'zod'
import { pingIp as defaultPingIp } from './icmp.js'
import { tcpPing as defaultTcpPing } from './tcp.js'
import { summary as pingSummary } from './analytics.js'
import { env as defaultEnv } from '../../config/env.js'

export const RESULT_KEYS = [
  'target',
  'method',
  'count',
  'sent',
  'received',
  'loss_pct',
  'min_ms',
  'avg_ms',
  'max_ms',
  'jitter_ms',
  'quality',
  'port',
  'ttl',
  'likely_os_family',
  'history_delta_ms',
  'geo',
  'error',
]

export const schema = z.object({
  target: z.string().trim().min(1).max(260),
  count: z.coerce.number().int().min(1).max(20).default(4),
})

function emptyResult(input) {
  return {
    target: input.target,
    method: 'tcp',
    count: input.count,
    sent: input.count,
    received: 0,
    loss_pct: 100,
    min_ms: null,
    avg_ms: null,
    max_ms: null,
    jitter_ms: null,
    quality: 'unreachable',
    port: null,
    ttl: null,
    likely_os_family: null,
    history_delta_ms: null,
    geo: {},
    error: null,
  }
}

function detectPing() {
  return existsSync('/bin/ping') || existsSync('/usr/bin/ping')
}

async function defaultHistoryGet() {
  const { getRedisClient } = await import('../../redis/client.js')
  return getRedisClient()
}

export function createPingDefinition({
  icmpPing = defaultPingIp,
  tcpPing = defaultTcpPing,
  platform = process.platform,
  hasPing = detectPing(),
  geo = null,
  history = null,
} = {}) {
  async function lookupGeo(ip, family) {
    if (geo) {
      try {
        return await geo(ip)
      } catch {
        return {}
      }
    }
    try {
      const { definition } = await import('../geoip/index.js')
      const data = await definition.execute(
        { target: ip },
        { target: { addresses: [{ address: ip, family }] }, env: defaultEnv }
      )
      return data.error ? {} : data
    } catch {
      return {}
    }
  }

  async function readHistory(ctx, targetKey) {
    if (history) return history.get(ctx.userId, targetKey)
    try {
      const client = await defaultHistoryGet()
      const value = await client.get(`cst:ping:last:${ctx.userId}:${targetKey}`)
      return value == null ? null : Number(value)
    } catch {
      return null
    }
  }

  async function writeHistory(ctx, targetKey, value) {
    if (history) return history.set(ctx.userId, targetKey, value)
    try {
      const client = await defaultHistoryGet()
      await client.set(
        `cst:ping:last:${ctx.userId}:${targetKey}`,
        String(value),
        'EX',
        defaultEnv.PING_HISTORY_TTL_SEC
      )
    } catch {}
  }

  return {
    name: 'ping',
    toolEnum: 'PING',
    schema,
    touchesTarget: true,
    dedupeTtlSec: 0,
    normalize: (input) => input,
    async execute(input, ctx) {
      const env = ctx.env ?? defaultEnv
      const address = ctx.target.addresses[0]
      const method = env.PING_METHOD
      const useIcmp =
        method === 'icmp' || (method === 'auto' && platform === 'linux' && hasPing)

      let parsed = null
      if (useIcmp) {
        try {
          parsed = await icmpPing(address.address, {
            count: input.count,
            family: address.family,
            signal: ctx.signal,
          })
          parsed.method = 'icmp'
        } catch (err) {
          if (method === 'icmp') throw err
        }
      }

      if (!parsed) {
        const tcp = await tcpPing({
          address: address.address,
          count: input.count,
          signal: ctx.signal,
        })
        parsed = { ...tcp, transmitted: tcp.sent, received: tcp.received, loss_pct: tcp.loss_pct }
        parsed.samples = tcp.values.filter((value) => value !== null)
      }

      const stats = pingSummary(parsed.samples, parsed.transmitted ?? input.count)
      const previous = await readHistory(ctx, input.target)
      const result = {
        ...emptyResult(input),
        method: parsed.method,
        sent: parsed.transmitted ?? input.count,
        received: parsed.received,
        loss_pct: parsed.loss_pct,
        min_ms: stats.min,
        avg_ms: stats.avg,
        max_ms: stats.max,
        jitter_ms: stats.jitter,
        quality: stats.quality,
        port: parsed.port ?? null,
        ttl: parsed.ttl ?? null,
        likely_os_family: parsed.likely_os_family ?? null,
        history_delta_ms: previous != null && stats.avg != null ? stats.avg - previous : null,
        geo: await lookupGeo(address.address, address.family),
      }
      if (stats.avg != null) await writeHistory(ctx, input.target, stats.avg)
      return result
    },
    emptyResult,
    summarize: (data) => ({
      avgMs: data.avg_ms,
      lossPct: data.loss_pct,
      quality: data.quality,
      method: data.method,
    }),
  }
}

export const definition = createPingDefinition()
definition.mode = 'auto'
definition.asyncWhen = (input) => input.count > 20
