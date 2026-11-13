import dns from 'node:dns'
import { safeHttp } from './safeHttp.js'
import { createBreaker } from './circuitBreaker.js'
import { ToolError } from '../tools/_shared/errors.js'

export const TYPE_NUMBERS = Object.freeze({
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  CAA: 257,
})

export const TYPE_NAMES = Object.freeze(
  Object.fromEntries(Object.entries(TYPE_NUMBERS).map(([name, number]) => [number, name]))
)

const PROVIDERS = [
  {
    name: 'Cloudflare DoH',
    host: 'cloudflare-dns.com',
    url: (name, type) =>
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
  },
  {
    name: 'Google DoH',
    host: 'dns.google',
    url: (name, type) =>
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
  },
]

const breaker = createBreaker({ name: 'doh' })

async function queryProvider(provider, name, type) {
  const response = await safeHttp.request(provider.url(name, type), {
    mode: 'trusted',
    allowHosts: [provider.host],
    headers: { accept: 'application/dns-json' },
    maxBytes: 256 * 1024,
    deadlineMs: 5000,
  })
  if (response.status !== 200) throw new ToolError('upstream', 'Lookup service unavailable')
  let body
  try {
    body = JSON.parse(response.body.toString('utf8'))
  } catch {
    throw new ToolError('upstream', 'Lookup service unavailable')
  }
  return { data: body, resolver: provider.name }
}

async function queryFallback(name, type) {
  const resolver = new dns.promises.Resolver({ timeout: 5000, tries: 1 })
  resolver.setServers(['1.1.1.1', '8.8.8.8'])
  try {
    const answers = await resolver.resolve(name, type)
    const ttl = answers.rrset?.ttl ?? null
    return {
      data: {
        Status: 0,
        Answer: answers.map((answer) => ({
          name,
          type: TYPE_NUMBERS[type] ?? 0,
          TTL: ttl,
          data: answer.toText?.(true) ?? String(answer),
        })),
      },
      resolver: 'Public DNS fallback',
    }
  } catch (err) {
    if (err?.code === 'ENOTFOUND' || err?.code === 'ENODATA' || err?.code === 'NXDOMAIN') {
      return { data: { Status: err.code === 'NXDOMAIN' ? 3 : 0 }, resolver: 'Public DNS fallback' }
    }
    throw new ToolError('upstream', 'Lookup service unavailable', err)
  }
}

export async function query(name, type = 'A') {
  let lastError
  try {
    return await breaker.exec(async () => {
      for (const provider of PROVIDERS) {
        try {
          return await queryProvider(provider, name, type)
        } catch (err) {
          lastError = err
        }
      }
      throw lastError ?? new ToolError('upstream', 'Lookup service unavailable')
    })
  } catch (err) {
    if (err instanceof ToolError && err.kind === 'upstream') {
      return queryFallback(name, type)
    }
    throw err
  }
}

export async function queryAll(name, types, { overallMs = 8000 } = {}) {
  const work = Promise.allSettled(
    types.map(async (type) => ({ type, ...(await query(name, type)) }))
  )
  let timer
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new ToolError('target', 'Query timed out')),
      overallMs
    )
  })
  let settled
  try {
    settled = await Promise.race([work, timeout])
  } catch (err) {
    if (err instanceof ToolError && err.message === 'Query timed out') {
      return types.map((type) => ({ type, error: err }))
    }
    throw err
  } finally {
    clearTimeout(timer)
  }
  return settled.map((entry, index) =>
    entry.status === 'fulfilled'
      ? entry.value
      : { type: types[index], error: entry.reason }
  )
}
