import { safeHttp as defaultSafeHttp } from '../../../net/safeHttp.js'
import { createBreaker } from '../../../net/circuitBreaker.js'
import { getRedisClient } from '../../../redis/client.js'

const TOR_URL = 'https://check.torproject.org/torbulkexitlist'
const SET_KEY = 'cst:geoip:tor:exits'
const UPDATED_KEY = 'cst:geoip:tor:updated'
export const TOR_REFRESH_SEC = 3600
export const TOR_STALE_SEC = 24 * 3600

const breaker = createBreaker({ name: 'geoip-tor' })

function isIpv4(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)
}

export function parseTorExitList(body) {
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body ?? '')
  return [...new Set(
    text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => isIpv4(line))
  )]
}

async function replaceSet(redis, ips, now) {
  if (typeof redis.multi === 'function') {
    const tx = redis.multi()
    tx.del(SET_KEY)
    if (ips.length > 0) tx.sadd(SET_KEY, ...ips)
    tx.set(UPDATED_KEY, String(now))
    await tx.exec()
    return
  }
  await redis.del(SET_KEY)
  if (ips.length > 0) await redis.sadd(SET_KEY, ...ips)
  await redis.set(UPDATED_KEY, String(now))
}

export async function torExitStatus(ip, {
  redis = getRedisClient(),
  client = defaultSafeHttp,
  now = Date.now(),
  forceRefresh = false,
} = {}) {
  try {
    const updated = Number(await redis.get(UPDATED_KEY)) || 0
    const ageSec = updated > 0 ? (now - updated) / 1000 : Infinity

    if (!forceRefresh && updated > 0 && ageSec < TOR_REFRESH_SEC) {
      if (ageSec > TOR_STALE_SEC) return null
      return Boolean(await redis.sismember(SET_KEY, ip))
    }

    try {
      const response = await breaker.exec(() =>
        client.request(TOR_URL, {
          mode: 'trusted',
          allowHosts: ['check.torproject.org'],
          deadlineMs: 10000,
          maxBytes: 4 * 1024 * 1024,
        })
      )
      if (response.status !== 200) throw new Error(`upstream status ${response.status}`)
      const ips = parseTorExitList(response.body)
      if (ips.length === 0) throw new Error('empty exit list')
      await replaceSet(redis, ips, now)
      return ips.includes(ip)
    } catch {
      if (updated > 0 && ageSec <= TOR_STALE_SEC) {
        return Boolean(await redis.sismember(SET_KEY, ip))
      }
      return null
    }
  } catch {
    return null
  }
}

export async function refreshTorExitList(options = {}) {
  return torExitStatus('0.0.0.0', { ...options, forceRefresh: true })
}
