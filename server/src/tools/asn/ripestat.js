import { safeHttp } from '../../net/safeHttp.js'
import { createBreaker } from '../../net/circuitBreaker.js'
import { cacheGet, cacheSet } from '../_shared/cache.js'

const HOST = 'stat.ripe.net'
const CACHE_NAME = 'asn:prefixes'
const CACHE_TTL_SEC = 24 * 60 * 60
const breaker = createBreaker({ name: 'ripestat' })

export async function announcedPrefixes(asn, {
  client = safeHttp,
  getCached = cacheGet,
  setCached = cacheSet,
  limit = 100,
} = {}) {
  const cached = await getCached(CACHE_NAME, asn)
  if (cached) return cached
  const url = `https://${HOST}/data/announced-prefixes/data.json?resource=${encodeURIComponent(asn)}`
  const response = await breaker.exec(() =>
    client.request(url, {
      mode: 'trusted',
      allowHosts: [HOST],
      deadlineMs: 8000,
      maxBytes: 512 * 1024,
    })
  )
  if (response.status !== 200) throw new Error('Lookup service unavailable')
  const json = JSON.parse(response.body.toString('utf8'))
  const prefixes = (json?.data?.prefixes ?? [])
    .map((entry) => entry?.prefix)
    .filter((prefix) => typeof prefix === 'string')
  const result = {
    prefixes: prefixes.slice(0, limit),
    prefix_count: prefixes.length,
    truncated: prefixes.length > limit,
  }
  await setCached(CACHE_NAME, asn, result, CACHE_TTL_SEC)
  return result
}
