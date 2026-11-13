import { createHash } from 'node:crypto'
import { env as defaultEnv } from '../../config/env.js'
import { cpeFor, parseVersionStrings, SERVICE_CPE_MAPPINGS } from './cpe.js'
import { getNvdClient } from '../../net/nvdClient.js'
import * as defaultCveRepo from '../../db/repos/cveRepo.js'

const inFlight = new Map()
const KNOWN_PRODUCTS = new Set(Object.values(SERVICE_CPE_MAPPINGS))

export function cveCacheKey(service, version) {
  return createHash('sha256')
    .update(`${String(service).toLowerCase()}|${String(version)}`)
    .digest('hex')
}

function severityRank(severity) {
  return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[String(severity).toUpperCase()] ?? 0
}

export function buildCveResult(serviceName, version, cves) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const cve of cves) {
    const key = String(cve.severity ?? '').toLowerCase()
    if (key in counts) counts[key] += 1
  }
  return {
    service_name: serviceName,
    version,
    cves,
    total_count: cves.length,
    critical_count: counts.critical,
    high_count: counts.high,
    medium_count: counts.medium,
    low_count: counts.low,
  }
}

function toCve(entry) {
  return {
    cve_id: entry.cve_id,
    description: String(entry.description ?? '').slice(0, 500),
    severity: String(entry.severity ?? 'UNKNOWN').toUpperCase(),
    cvss_score: entry.cvss_score == null ? null : Number(entry.cvss_score),
    cvss_vector: entry.cvss_vector ?? null,
    published_date: entry.published_date ?? null,
    url: entry.url ?? `https://nvd.nist.gov/vuln/detail/${entry.cve_id}`,
  }
}

export function attachCvesToPort(port, cveResult) {
  if (!cveResult) {
    port.cve_result = null
    port.cve_count = 0
    port.cve_critical_count = 0
    port.cve_high_count = 0
    port.cve_medium_count = 0
    port.cve_low_count = 0
    port.max_cvss_score = null
    port.max_cvss_severity = null
    port.max_cvss_cve = null
    return port
  }

  port.cve_result = cveResult
  port.cve_count = cveResult.total_count
  port.cve_critical_count = cveResult.critical_count
  port.cve_high_count = cveResult.high_count
  port.cve_medium_count = cveResult.medium_count
  port.cve_low_count = cveResult.low_count

  let best = null
  for (const cve of cveResult.cves) {
    if (cve.cvss_score == null) continue
    if (
      !best ||
      cve.cvss_score > best.cvss_score ||
      (cve.cvss_score === best.cvss_score && severityRank(cve.severity) > severityRank(best.severity))
    ) {
      best = cve
    }
  }
  port.max_cvss_score = best?.cvss_score ?? null
  port.max_cvss_severity = best?.severity ?? null
  port.max_cvss_cve = best?.cve_id ?? null
  return port
}

export function createCveDetector({
  env = defaultEnv,
  nvdClient = null,
  cveRepo = defaultCveRepo,
  logger = console,
  now = () => new Date(),
} = {}) {
  const client = nvdClient ?? getNvdClient()
  const state = { error: null }

  async function lookupOne(service, version) {
    const cacheKey = cveCacheKey(service, version)
    try {
      const cached = await cveRepo.getServiceLookup(cacheKey)
      if (cached) {
        const cves = (await cveRepo.findCvesByIds(cached.cveIds))
          .map(toCve)
          .filter((cve) => (cve.cvss_score ?? 0) >= env.NVD_MIN_CVSS_SCORE)
          .sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
          .slice(0, env.NVD_MAX_RESULTS_PER_SERVICE)
        return cves
      }
    } catch (err) {
      logger.warn?.({ err, service, version }, 'CVE cache read failed')
    }

    const key = `${service}|${version}`
    if (inFlight.has(key)) return inFlight.get(key)

    const promise = (async () => {
      let fetched
      try {
        fetched = await client.lookupByCpe(cpeFor(service, version), env.NVD_MAX_RESULTS_PER_SERVICE * 2)
      } catch (err) {
        state.error = 'Lookup service unavailable'
        logger.warn?.({ err, service, version }, 'CVE lookup failed')
        return []
      }

      const cves = fetched
        .map(toCve)
        .filter((cve) => (cve.cvss_score ?? 0) >= env.NVD_MIN_CVSS_SCORE)
        .sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
        .slice(0, env.NVD_MAX_RESULTS_PER_SERVICE)

      try {
        await cveRepo.upsertCves(cves, { ttlHours: env.NVD_CACHE_TTL_HOURS, now: now() })
        await cveRepo.putServiceLookup({
          service,
          version,
          cveIds: cves.map((cve) => cve.cve_id),
          cacheKey,
          ttlHours: env.NVD_CACHE_TTL_HOURS,
          now: now(),
        })
      } catch (err) {
        logger.warn?.({ err, service, version }, 'CVE cache write failed')
      }

      return cves
    })().finally(() => inFlight.delete(key))

    inFlight.set(key, promise)
    return promise
  }

  async function detectCvesBatch(versionStrings, { signal } = {}) {
    state.error = null
    const unique = [...new Set((versionStrings ?? []).filter(Boolean))]
    const output = {}
    const results = new Map()

    for (const versionString of unique) {
      if (signal?.aborted) break
      const products = parseVersionStrings(versionString).filter(([service]) =>
        KNOWN_PRODUCTS.has(service)
      )
      if (!products.length) continue

      const merged = new Map()
      for (const [service, version] of products) {
        const cves = await lookupOne(service, version)
        for (const cve of cves) merged.set(cve.cve_id, cve)
      }

      const cves = [...merged.values()]
        .sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
        .slice(0, env.NVD_MAX_RESULTS_PER_SERVICE)
      results.set(
        versionString,
        buildCveResult(products[0][0], versionString, cves)
      )
    }

    for (const [versionString, result] of results) output[versionString] = result
    Object.defineProperty(output, 'cve_error', {
      value: state.error,
      enumerable: false,
      configurable: true,
    })
    return output
  }

  return {
    detectCvesBatch,
    lookupOne,
    get error() {
      return state.error
    },
  }
}

export async function detectCvesBatch(versionStrings, options = {}) {
  return createCveDetector(options).detectCvesBatch(versionStrings, options)
}
