import dns from 'node:dns'
import ipaddr from 'ipaddr.js'
import { cacheGet, cacheSet } from '../../_shared/cache.js'

const CACHE_TTL_SEC = 24 * 60 * 60
const CACHE_NAME = 'geoip:cymru'

function resolverFor(timeoutMs) {
  const resolver = new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 })
  resolver.setServers(['1.1.1.1', '8.8.8.8'])
  return resolver
}

function flattenTxt(records) {
  return (records ?? []).map((record) => (Array.isArray(record) ? record.join('') : String(record)))
}

function fields(line) {
  return line.split('|').map((field) => field.trim())
}

function reversedIpv6(ip) {
  const bytes = ipaddr.parse(ip).toByteArray()
  return bytes
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .split('')
    .reverse()
    .join('.')
}

function originQuery(ip) {
  const parsed = ipaddr.parse(ip)
  if (parsed.kind() === 'ipv4') {
    return `${ip.split('.').reverse().join('.')}.origin.asn.cymru.com`
  }
  return `${reversedIpv6(ip)}.origin6.asn.cymru.com`
}

function prefixMatches(ip, cidr) {
  try {
    const [network, bits] = ipaddr.parseCIDR(cidr)
    return ipaddr.parse(ip).match(network, bits)
  } catch {
    return false
  }
}

export function parseOriginTxt(records, ip) {
  const lines = flattenTxt(records).flatMap((record) => record.split(/\r?\n/))
  const parsed = lines
    .map((line) => fields(line))
    .filter((parts) => parts.length >= 5 && /^\d+$/.test(parts[0]) && parts[1].includes('/'))
    .map((parts) => ({
      asn: `AS${parts[0]}`,
      prefix: parts[1],
      country: parts[2] || null,
      rir: parts[3] || null,
      allocated: parts[4] || null,
    }))
  if (parsed.length === 0) return null
  const matching = parsed.find((entry) => prefixMatches(ip, entry.prefix))
  return matching ?? parsed[0]
}

export function parseAsnNameTxt(records) {
  const lines = flattenTxt(records).flatMap((record) => record.split(/\r?\n/))
  for (const line of lines) {
    const parts = fields(line)
    if (parts.length >= 5 && /^\d+$/.test(parts[0])) {
      return {
        asn: `AS${parts[0]}`,
        country: parts[1] || null,
        rir: parts[2] || null,
        allocated: parts[3] || null,
        name: parts.slice(4).join(' | ') || null,
      }
    }
  }
  return null
}

export async function cymruAsnInfo(asn, {
  resolver = resolverFor(2000),
  getCached = cacheGet,
  setCached = cacheSet,
} = {}) {
  const normalized = `AS${String(asn).replace(/^AS/i, '')}`
  const cached = await getCached(CACHE_NAME, normalized)
  if (cached) return cached
  const records = await resolver.resolveTxt(`${normalized}.asn.cymru.com`)
  const parsed = parseAsnNameTxt(records)
  if (!parsed) return null
  await setCached(CACHE_NAME, normalized, parsed, CACHE_TTL_SEC)
  return parsed
}

export async function cymruAsn(ip, {
  resolver = resolverFor(2000),
  getCached = cacheGet,
  setCached = cacheSet,
} = {}) {
  const cached = await getCached(CACHE_NAME, ip)
  if (cached) return cached

  const originRecords = await resolver.resolveTxt(originQuery(ip))
  const origin = parseOriginTxt(originRecords, ip)
  if (!origin) return null

  const nameRecords = await resolver.resolveTxt(`${origin.asn}.asn.cymru.com`).catch(() => [])
  const name = parseAsnNameTxt(nameRecords)

  const result = {
    asn: origin.asn,
    name: name?.name ?? null,
    prefix: origin.prefix,
    rir: name?.rir ?? origin.rir,
    allocated: name?.allocated ?? origin.allocated,
    country: origin.country ?? name?.country ?? null,
  }
  await setCached(CACHE_NAME, ip, result, CACHE_TTL_SEC)
  return result
}
