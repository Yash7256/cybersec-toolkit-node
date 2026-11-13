import ipaddr from 'ipaddr.js'
import { safeHttp } from './safeHttp.js'
import { createBreaker } from './circuitBreaker.js'
import { cacheGet, cacheSet } from '../tools/_shared/cache.js'
import { ToolError } from '../tools/_shared/errors.js'
import { env as defaultEnv } from '../config/env.js'

const BOOTSTRAP = {
  dns: 'https://data.iana.org/rdap/dns.json',
  ipv4: 'https://data.iana.org/rdap/ipv4.json',
  ipv6: 'https://data.iana.org/rdap/ipv6.json',
}
const BOOTSTRAP_TTL_SEC = 24 * 60 * 60
const memory = new Map()
const breaker = createBreaker({ name: 'rdap' })

async function loadBootstrap(name) {
  if (memory.has(name)) return memory.get(name)
  const cached = await cacheGet('rdap:bootstrap', name)
  if (cached) {
    memory.set(name, cached)
    return cached
  }
  const response = await safeHttp.request(BOOTSTRAP[name], {
    mode: 'trusted',
    allowHosts: ['data.iana.org'],
    maxBytes: 2 * 1024 * 1024,
  })
  if (response.status !== 200) throw new ToolError('upstream', 'Lookup service unavailable')
  const json = JSON.parse(response.body.toString('utf8'))
  memory.set(name, json)
  await cacheSet('rdap:bootstrap', name, json, BOOTSTRAP_TTL_SEC)
  return json
}

function httpsUrl(urls = []) {
  return urls.find((url) => url.startsWith('https://')) ?? null
}

export async function findServer(tld) {
  try {
    const json = await loadBootstrap('dns')
    const key = String(tld).toLowerCase()
    for (const [services, urls] of json.services ?? []) {
      if (services.some((service) => String(service).toLowerCase() === key)) {
        return httpsUrl(urls)
      }
    }
  } catch {}
  return null
}

export async function findServerForIp(ip) {
  let parsed
  try {
    parsed = ipaddr.parse(ip)
  } catch {
    return null
  }
  const name = parsed.kind() === 'ipv6' ? 'ipv6' : 'ipv4'
  try {
    const json = await loadBootstrap(name)
    let best = null
    let bestBits = -1
    for (const [services, urls] of json.services ?? []) {
      for (const service of services) {
        try {
          const [range, bits] = ipaddr.parseCIDR(service)
          if (parsed.kind() !== range.kind()) continue
          if (parsed.match(range, bits) && bits > bestBits) {
            const url = httpsUrl(urls)
            if (url) {
              best = url
              bestBits = bits
            }
          }
        } catch {}
      }
    }
    return best
  } catch {
    return null
  }
}

async function requestJson(url, allowHosts) {
  const response = await breaker.exec(() =>
    safeHttp.request(url, {
      mode: 'trusted',
      allowHosts,
      maxBytes: 512 * 1024,
      deadlineMs: defaultEnv.WHOIS_TIMEOUT_MS,
    })
  )
  if (response.status === 404) return { found: false }
  if (response.status === 429 || response.status >= 500) {
    throw new ToolError('upstream', 'Lookup service unavailable')
  }
  if (response.status !== 200) throw new ToolError('upstream', 'Lookup service unavailable')
  try {
    return { found: true, data: JSON.parse(response.body.toString('utf8')) }
  } catch {
    throw new ToolError('upstream', 'Lookup service unavailable')
  }
}

export async function queryDomain(domain, { server } = {}) {
  const base = server ?? (await findServer(String(domain).split('.').pop())) ?? 'https://rdap.org'
  const host = new URL(base).hostname
  const url = `${base.replace(/\/$/, '')}/domain/${encodeURIComponent(domain)}`
  return requestJson(url, [host])
}

export async function queryIp(ip, { server } = {}) {
  const base = server ?? (await findServerForIp(ip)) ?? 'https://rdap.org'
  const host = new URL(base).hostname
  const url = `${base.replace(/\/$/, '')}/ip/${encodeURIComponent(ip)}`
  return requestJson(url, [host])
}
