import { env as defaultEnv } from '../config/env.js'
import { safeHttp as defaultSafeHttp } from './safeHttp.js'
import { createOutboundLimiter } from '../security/outboundLimiter.js'
import { createBreaker } from './circuitBreaker.js'
import { ToolError } from '../tools/_shared/errors.js'
import { cvssScoreToSeverity } from '../scanner/cve/cpe.js'

const NVD_HOST = 'services.nvd.nist.gov'
const NVD_PATH = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const RETRY_STATUSES = new Set([403, 429, 503])
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function pickEnglish(descriptions) {
  if (!Array.isArray(descriptions)) return ''
  const english = descriptions.find((item) => item?.lang === 'en')
  return String((english ?? descriptions[0])?.value ?? '')
}

function pickCvss(metrics) {
  const v31 = metrics?.cvssMetricV31?.[0]?.cvssData
  if (v31) {
    return {
      score: v31.baseScore ?? null,
      severity: String(v31.baseSeverity ?? '').toUpperCase() || cvssScoreToSeverity(v31.baseScore),
      vector: v31.vectorString ?? null,
    }
  }
  const v30 = metrics?.cvssMetricV30?.[0]?.cvssData
  if (v30) {
    return {
      score: v30.baseScore ?? null,
      severity: String(v30.baseSeverity ?? '').toUpperCase() || cvssScoreToSeverity(v30.baseScore),
      vector: v30.vectorString ?? null,
    }
  }
  const v2 = metrics?.cvssMetricV2?.[0]
  if (v2?.cvssData) {
    return {
      score: v2.cvssData.baseScore ?? null,
      severity: String(v2.baseSeverity ?? '').toUpperCase() || cvssScoreToSeverity(v2.cvssData.baseScore),
      vector: v2.cvssData.vectorString ?? null,
    }
  }
  return { score: null, severity: 'UNKNOWN', vector: null }
}

export function parseNvdResponse(payload) {
  const vulnerabilities = payload?.vulnerabilities
  if (!Array.isArray(vulnerabilities)) return []

  const cves = []
  for (const vulnerability of vulnerabilities) {
    const cve = vulnerability?.cve
    if (!cve?.id) continue
    if (String(cve.vulnStatus ?? '').toLowerCase() === 'rejected') continue

    const cvss = pickCvss(cve.metrics)
    cves.push({
      cve_id: cve.id,
      description: pickEnglish(cve.descriptions).slice(0, 500),
      severity: cvss.severity,
      cvss_score: cvss.score,
      cvss_vector: cvss.vector,
      published_date: cve.published ?? null,
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    })
  }
  return cves
}

export function createNvdClient({
  env = defaultEnv,
  http = defaultSafeHttp,
  limiter = null,
  breaker = createBreaker({ name: 'nvd' }),
  sleepFn = sleep,
  random = Math.random,
  retries = 3,
} = {}) {
  const rateLimiter =
    limiter ??
    createOutboundLimiter({
      name: 'nvd',
      points: env.NVD_API_KEY ? 50 : 5,
      durationSec: 30,
      maxWaitMs: 30000,
    })

  async function fetchPage({ cpeName = null, keyword = null, resultsPerPage }) {
    const params = new URLSearchParams()
    if (cpeName) params.set('cpeName', cpeName)
    else if (keyword) params.set('keywordSearch', keyword)
    params.set('resultsPerPage', String(Math.max(1, Math.min(200, resultsPerPage))))
    const url = `${NVD_PATH}?${params.toString()}`
    const headers = { accept: 'application/json' }
    if (env.NVD_API_KEY) headers.apiKey = env.NVD_API_KEY

    let lastError = null
    for (let attempt = 1; attempt <= retries; attempt += 1) {
      let response
      try {
        await rateLimiter.acquire()
        response = await breaker.exec(() =>
          http.request(url, {
            mode: 'trusted',
            allowHosts: [NVD_HOST],
            headers,
            deadlineMs: 15000,
            maxBytes: 2 * 1024 * 1024,
          })
        )
      } catch (err) {
        lastError = err
        if (attempt >= retries) break
        await sleepFn(Math.min(4000, 250 * 2 ** (attempt - 1)) + Math.floor(random() * 100))
        continue
      }

      if (RETRY_STATUSES.has(response.status) && attempt < retries) {
        lastError = new ToolError('upstream', 'Lookup service unavailable')
        await sleepFn(Math.min(4000, 250 * 2 ** (attempt - 1)) + Math.floor(random() * 100))
        continue
      }
      if (response.status < 200 || response.status >= 300) {
        throw new ToolError('upstream', 'Lookup service unavailable')
      }

      try {
        return parseNvdResponse(JSON.parse(response.body.toString('utf8')))
      } catch (err) {
        throw new ToolError('upstream', 'Lookup service unavailable', err)
      }
    }

    throw lastError ?? new ToolError('upstream', 'Lookup service unavailable')
  }

  return {
    async lookupByCpe(cpeName, resultsPerPage = defaultEnv.NVD_MAX_RESULTS_PER_SERVICE) {
      return fetchPage({ cpeName, resultsPerPage })
    },
    async lookupByKeyword(keyword, resultsPerPage = defaultEnv.NVD_MAX_RESULTS_PER_SERVICE) {
      return fetchPage({ keyword, resultsPerPage })
    },
  }
}

let singleton = null
export function getNvdClient() {
  if (!singleton) singleton = createNvdClient()
  return singleton
}
