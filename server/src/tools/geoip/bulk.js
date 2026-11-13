import { z } from 'zod'
import { createHash } from 'node:crypto'
import { validateTarget } from '../../security/targetPolicy.js'
import { definition as geoipDefinition } from './index.js'
import { env as defaultEnv } from '../../config/env.js'
import AppError from '../../utils/AppError.js'

export const schema = z.object({
  targets: z.array(z.string().trim().min(1).max(260)).min(1).max(100),
})

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length)
  let next = 0
  async function worker() {
    while (next < items.length) {
      const index = next
      next += 1
      results[index] = await fn(items[index], index)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return results
}

function bulkKey(targets) {
  return `bulk:${createHash('sha256').update(targets.join('\n')).digest('hex').slice(0, 32)}`
}

export function emptyResult(input) {
  return {
    target: 'bulk',
    mode: 'bulk',
    total: 0,
    completed: 0,
    failed: 0,
    rejected: [],
    summary: { countries: {}, asns: {}, ip_types: {}, cdn: 0, hosting: 0, tor: 0 },
    ip_results: [],
    results: [],
    warnings: [],
    error: null,
  }
}

export function createBulkDefinition({
  geoip = geoipDefinition,
  env = defaultEnv,
  validate = validateTarget,
  lookup = (target, ctx) => geoip.execute({ target }, ctx),
} = {}) {
  return {
    name: 'geoip_bulk',
    toolEnum: 'GEOIP_BULK',
    schema,
    touchesTarget: false,
    dedupeTtlSec: 0,
    mode: 'async',
    normalize: (input) => ({ ...input, target: 'bulk' }),
    async validateInput(input, { req } = {}) {
      const tier = req?.user?.role === 'ADMIN' || req?.user?.tier === 'PAID' ? 'PAID' : 'FREE'
      const max = tier === 'PAID' ? env.GEOIP_BULK_MAX_PAID : env.GEOIP_BULK_MAX_FREE
      const seen = new Set()
      const unique = []
      for (const raw of input.targets) {
        const value = raw.trim()
        if (!value || seen.has(value.toLowerCase())) continue
        seen.add(value.toLowerCase())
        unique.push(value)
      }
      const checked = await mapLimit(unique, 8, async (value) => {
        try {
          await validate(value, { env })
          return { value, ok: true }
        } catch (err) {
          return { value, ok: false, reason: err?.message ?? 'Invalid target' }
        }
      })
      const targets = checked.filter((entry) => entry.ok).map((entry) => entry.value)
      const rejected = checked
        .filter((entry) => !entry.ok)
        .map((entry) => ({ input: entry.value, reason: entry.reason }))
      if (targets.length === 0) {
        throw new AppError(422, 'VALIDATION_ERROR', 'No valid targets in the bulk request', { rejected })
      }
      if (targets.length > max) {
        throw new AppError(422, 'VALIDATION_ERROR', `Bulk lookup is limited to ${max} targets on your plan`, {
          max,
          received: targets.length,
        })
      }
      input.targets = targets
      input.rejected = rejected
      return { targetKey: bulkKey(targets), addresses: [], display: `bulk (${targets.length})` }
    },
    quotaUnits: (input) => input.targets.length,
    async execute(input, ctx) {
      const targets = input.targets ?? []
      const outcomes = await mapLimit(targets, 4, async (target, index) => {
        if (ctx?.signal?.aborted) throw new AppError(504, 'TOOL_TIMEOUT', 'Request timed out')
        try {
          const data = await lookup(target, ctx)
          ctx?.reportProgress?.(Math.round(((index + 1) / targets.length) * 100))
          return { input: target, status: 'ok', data }
        } catch (err) {
          return { input: target, status: 'error', error: err?.message ?? 'Lookup failed' }
        }
      })
      const ok = outcomes.filter((row) => row.status === 'ok')
      const summary = { countries: {}, asns: {}, ip_types: {}, cdn: 0, hosting: 0, tor: 0 }
      for (const row of ok) {
        const data = row.data
        if (data.country_code) summary.countries[data.country_code] = (summary.countries[data.country_code] ?? 0) + 1
        if (data.asn) summary.asns[data.asn] = (summary.asns[data.asn] ?? 0) + 1
        if (data.ip_type) summary.ip_types[data.ip_type] = (summary.ip_types[data.ip_type] ?? 0) + 1
        if (data.is_cdn) summary.cdn += 1
        if (data.privacy?.hosting) summary.hosting += 1
        if (data.privacy?.tor) summary.tor += 1
      }
      return {
        ...emptyResult(input),
        target: 'bulk',
        total: targets.length,
        completed: ok.length,
        failed: outcomes.length - ok.length,
        rejected: input.rejected ?? [],
        summary,
        ip_results: ok.flatMap((row) => row.data.ip_results ?? []),
        results: outcomes.map((row) => row.status === 'ok'
          ? {
              input: row.input,
              status: 'ok',
              ip: row.data.ip ?? null,
              country_code: row.data.country_code ?? null,
              city: row.data.city ?? null,
              asn: row.data.asn ?? null,
              org: row.data.org ?? null,
              ip_type: row.data.ip_type ?? null,
            }
          : { input: row.input, status: 'error', error: row.error }),
        warnings: [...new Set(ok.flatMap((row) => (row.data.warnings ?? []).map((warning) => warning.source)))].map((source) => ({ source, message: 'Source unavailable' })),
      }
    },
    emptyResult,
    summarize: (data) => ({ total: data.total, completed: data.completed, failed: data.failed, rejected: data.rejected?.length ?? 0 }),
  }
}

export const definition = createBulkDefinition()
