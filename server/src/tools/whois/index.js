import net from 'node:net'
import { z } from 'zod'
import { getDomain } from 'tldts'
import { queryDomain, queryIp } from '../../net/rdapClient.js'
import { classifyAddress } from '../../security/resolve.js'
import { normalizeRdap } from './rdapNormalize.js'
import { port43Lookup } from './port43.js'
import { cacheGet, cacheSet } from '../_shared/cache.js'
import { ToolError } from '../_shared/errors.js'
import { env as defaultEnv } from '../../config/env.js'

export const RESULT_KEYS = [
  'target',
  'domain',
  'available',
  'registrar',
  'creation_date',
  'expiration_date',
  'updated_date',
  'name_servers',
  'status',
  'dnssec',
  'privacy_protected',
  'days_until_expiry',
  'expiry_status',
  'summary',
  'error',
  'rdap_available',
  'normalized',
  'rdap',
  'cached',
]

export const schema = z.object({ target: z.string().trim().min(1).max(260) })

const emptyResult = (input) => ({
  target: input.target,
  domain: input.target,
  available: false,
  registrar: null,
  creation_date: null,
  expiration_date: null,
  updated_date: null,
  name_servers: [],
  status: [],
  dnssec: null,
  privacy_protected: false,
  days_until_expiry: null,
  expiry_status: null,
  summary: null,
  error: null,
  rdap_available: false,
  normalized: null,
  rdap: null,
  cached: false,
})

function normalizeTarget(value) {
  const raw = value.trim()
  const host = /^https?:\/\//i.test(raw) ? new URL(raw).hostname : raw.split('/')[0]
  const cleaned = host.replace(/^www\./i, '').toLowerCase()
  if (net.isIP(cleaned)) {
    classifyAddress(cleaned)
    return { target: cleaned, isIp: true }
  }
  const domain = getDomain(cleaned, { allowPrivateDomains: false })
  if (!domain) throw new ToolError('target', 'Target returned an invalid response')
  return { target: domain, isIp: false }
}

export function createWhoisDefinition({
  rdap = { queryDomain, queryIp },
  legacy = port43Lookup,
  getCached = cacheGet,
  setCached = cacheSet,
  env = defaultEnv,
} = {}) {
  return {
    name: 'whois',
    toolEnum: 'WHOIS',
    schema,
    touchesTarget: false,
    dedupeTtlSec: 3600,
    normalize(input) {
      return { ...input, ...normalizeTarget(input.target) }
    },
    async execute(input) {
      const cached = await getCached('whois', input.target)
      if (cached) return { ...cached, cached: true }

      let result
      try {
        if (input.isIp) {
          const response = await rdap.queryIp(input.target)
          result = response.found
            ? normalizeRdap(input.target, response.data)
            : { ...emptyResult(input), available: true, error: 'Not registered' }
        } else {
          const response = await rdap.queryDomain(input.target)
          if (response.found) {
            result = normalizeRdap(input.target, response.data)
          } else {
            const fallback = await legacy(input.target)
            result = { ...emptyResult(input), ...fallback, rdap_available: false }
          }
        }
      } catch (err) {
        if (err instanceof ToolError && err.kind === 'target') throw err
        try {
          const fallback = await legacy(input.target)
          result = { ...emptyResult(input), ...fallback, rdap_available: false }
        } catch {
          throw new ToolError('upstream', 'Lookup service unavailable')
        }
      }

      result.cached = false
      try {
        await setCached('whois', input.target, result, env.WHOIS_CACHE_TTL_SEC)
      } catch {}
      return result
    },
    emptyResult,
    summarize: (data) => ({
      registrar: data.registrar,
      expiryStatus: data.expiry_status,
      daysUntilExpiry: data.days_until_expiry,
      privacyProtected: data.privacy_protected,
      available: data.available,
    }),
  }
}

export const definition = createWhoisDefinition()
