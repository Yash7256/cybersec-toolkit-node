import { env as defaultEnv } from '../../config/env.js'
import { classifyIp } from '../../security/ipPolicy.js'
import { schema, inputShape } from './schema.js'
import { WORDLISTS, MAX_WORDLIST_SIZE } from './wordlists.js'
import { createResolver } from './resolve.js'
import { detectWildcard, markWildcardEntries } from './wildcard.js'
import { probeSubdomain } from './probe.js'
import { classifySubdomainRisk, computeConfidence } from './risk.js'

export const RESULT_KEYS = Object.freeze([
  'domain',
  'found',
  'total_checked',
  'total_found',
  'error',
  'wildcard_detected',
  'wildcard_ips',
  'scan_time_ms',
  'dns_ms',
  'http_ms',
])

const PRIVATE_REASONS = new Set(['private', 'loopback', 'link_local', 'cgnat', 'metadata'])

export function emptySubdomainResult(input = {}) {
  return {
    domain: input.domain ?? null,
    found: [],
    total_checked: 0,
    total_found: 0,
    error: null,
    wildcard_detected: false,
    wildcard_ips: [],
    scan_time_ms: 0,
    dns_ms: 0,
    http_ms: 0,
  }
}

export async function mapLimit(items, limit, fn) {
  const results = new Array(items.length)
  let index = 0
  const workers = Array.from({ length: Math.min(Math.max(1, limit), items.length) }, async () => {
    while (index < items.length) {
      const current = index
      index += 1
      results[current] = await fn(items[current], current)
    }
  })
  await Promise.all(workers)
  return results
}

function addressAllowed(address, allowPrivate) {
  const result = classifyIp(address)
  return result.allowed || (allowPrivate && PRIVATE_REASONS.has(result.reason))
}

export function createSubdomainDefinition({
  env = defaultEnv,
  resolve = null,
  wildcard = detectWildcard,
  probe = probeSubdomain,
  now = Date.now,
} = {}) {
  return {
    name: 'subdomain',
    toolEnum: 'SUBDOMAIN',
    schema,
    inputShape,
    touchesTarget: false,
    mode: 'async',
    timeoutMs: 300000,
    dedupeTtlSec: 300,
    maxWords: MAX_WORDLIST_SIZE,
    normalize(input) {
      const domain = input.domain.replace(/\.$/, '').toLowerCase()
      return {
        ...input,
        domain,
        target: domain,
        wordlist: input.wordlist ?? 'small',
        strictness: input.strictness ?? 'medium',
      }
    },
    emptyResult: emptySubdomainResult,
    async execute(input, ctx = {}) {
      const runEnv = ctx.env ?? env
      const signal = ctx.signal
      const reportProgress = ctx.reportProgress ?? (() => {})
      const started = now()
      const domain = input.domain
      const entries = WORDLISTS[input.wordlist] ?? WORDLISTS.small
      const totalChecked = entries.length
      const allowPrivate = Boolean(runEnv.ALLOW_PRIVATE_TARGETS)
      const resolver = resolve ?? createResolver({ env: runEnv, signal })

      let wildcardDetected = false
      let wildcardIps = []
      if (input.strictness !== 'off') {
        reportProgress(5)
        const result = await wildcard(domain, { env: runEnv, signal })
        wildcardDetected = Boolean(result?.detected)
        wildcardIps = Array.isArray(result?.ips) ? result.ips : []
      }

      reportProgress(10)
      const dnsStarted = now()
      let results = await mapLimit(entries, runEnv.SUBDOMAIN_DNS_CONCURRENCY, async (sub) => {
        if (signal?.aborted) throw new Error('aborted')
        return resolver(`${sub}.${domain}`)
      })
      const dnsMs = now() - dnsStarted

      if (wildcardDetected && wildcardIps.length > 0) {
        results = markWildcardEntries(results, wildcardIps, input.strictness)
        if (input.strictness === 'medium' || input.strictness === 'high') {
          results = results.filter((entry) => !entry.wildcard)
        }
      }

      reportProgress(55)
      const probeTargets = []
      for (const entry of results) {
        if (!entry.resolved) continue
        const addresses = [...(entry.records?.A ?? []), ...(entry.records?.AAAA ?? [])]
        if (addresses.length === 0 || addresses.every((address) => addressAllowed(address, allowPrivate))) {
          probeTargets.push(entry)
        } else {
          entry.http = {
            alive: false,
            skipped_reason: 'resolves to non-public address, HTTP probe blocked for safety',
          }
        }
      }

      const httpStarted = now()
      let probed = 0
      await mapLimit(probeTargets, runEnv.SUBDOMAIN_HTTP_CONCURRENCY, async (entry) => {
        if (signal?.aborted) throw new Error('aborted')
        entry.http = await probe(entry.subdomain, { env: runEnv, signal })
        probed += 1
        if (probed % 10 === 0) reportProgress(55 + Math.round((probed / probeTargets.length) * 35))
      })
      const httpMs = now() - httpStarted

      for (const entry of results) {
        if (entry.resolved) entry.risk = classifySubdomainRisk(entry.subdomain, entry.http)
        const confidence = computeConfidence(entry, wildcardIps)
        entry.verified = confidence.verified
        entry.confidence = confidence.confidence
      }

      reportProgress(100)
      const totalFound = results.filter((entry) => entry.resolved).length
      return {
        ...emptySubdomainResult(input),
        domain,
        found: results,
        total_checked: totalChecked,
        total_found: totalFound,
        wildcard_detected: wildcardDetected,
        wildcard_ips: wildcardIps,
        scan_time_ms: now() - started,
        dns_ms: dnsMs,
        http_ms: httpMs,
      }
    },
    summarize(data) {
      const found = Array.isArray(data.found) ? data.found : []
      return {
        total_checked: data.total_checked ?? 0,
        total_found: data.total_found ?? 0,
        verified: found.filter((entry) => entry.verified).length,
        high_risk: found.filter((entry) => entry.risk?.level === 'HIGH').length,
        wildcard_detected: Boolean(data.wildcard_detected),
      }
    },
  }
}

export const definition = createSubdomainDefinition()
export { schema }
