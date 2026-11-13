import { z } from 'zod'
import { cymruAsnInfo } from '../geoip/sources/cymru.js'
import { announcedPrefixes } from './ripestat.js'
import { env as defaultEnv } from '../../config/env.js'

export const schema = z.object({
  asn: z.string().trim().regex(/^(?:AS)?\d{1,10}$/i, 'Must be an ASN such as AS15169'),
})

export function normalizeAsn(value) {
  return `AS${String(value).replace(/^AS/i, '')}`
}

export function emptyResult(input) {
  return {
    target: input?.asn ?? null,
    asn: input?.asn ?? null,
    name: null,
    country: null,
    rir: null,
    allocated: null,
    prefixes: [],
    prefix_count: null,
    truncated: false,
    warnings: [],
    error: null,
    cached: false,
  }
}

export function createAsnDefinition({
  cymru = cymruAsnInfo,
  ripestat = announcedPrefixes,
  env = defaultEnv,
} = {}) {
  return {
    name: 'asn',
    toolEnum: 'ASN',
    schema,
    touchesTarget: false,
    dedupeTtlSec: 86400,
    normalize: (input) => ({ ...input, asn: normalizeAsn(input.asn), target: normalizeAsn(input.asn) }),
    validateInput: (input) => ({
      targetKey: input.asn.toLowerCase(),
      addresses: [],
      display: input.asn,
    }),
    async execute(input) {
      const asn = normalizeAsn(input.asn)
      const warnings = []
      const [info, prefixes] = await Promise.all([
        cymru(asn).catch((err) => {
          warnings.push({ source: 'team-cymru', message: err?.message ?? 'ASN lookup unavailable' })
          return null
        }),
        ripestat(asn).catch((err) => {
          warnings.push({ source: 'ripestat', message: err?.message ?? 'Prefix lookup unavailable' })
          return null
        }),
      ])
      if (!info && !prefixes) {
        throw Object.assign(new Error('Lookup service unavailable'), { kind: 'upstream' })
      }
      return {
        ...emptyResult(input),
        target: asn,
        asn,
        name: info?.name ?? null,
        country: info?.country ?? null,
        rir: info?.rir ?? null,
        allocated: info?.allocated ?? null,
        prefixes: prefixes?.prefixes ?? [],
        prefix_count: prefixes?.prefix_count ?? null,
        truncated: prefixes?.truncated ?? false,
        warnings,
      }
    },
    emptyResult,
    summarize: (data) => ({ asn: data.asn, name: data.name, prefix_count: data.prefix_count }),
  }
}

export const definition = createAsnDefinition()
