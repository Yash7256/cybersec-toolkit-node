import dns from 'node:dns'
import ipaddr from 'ipaddr.js'
import { queryIp } from '../../net/rdapClient.js'
import { cacheGet, cacheSet } from '../_shared/cache.js'

const RDAP_CACHE_NAME = 'geoip:rdap'
const RDAP_CACHE_TTL_SEC = 24 * 60 * 60

const CDN_PROVIDERS = [
  { name: 'Cloudflare', pattern: /\bcloudflare\b/i },
  { name: 'Akamai', pattern: /\bakamai\b/i },
  { name: 'Fastly', pattern: /\bfastly\b/i },
  { name: 'Amazon CloudFront', pattern: /\bcloudfront\b/i },
  { name: 'Imperva', pattern: /\bimperva\b|\bincapsula\b/i },
  { name: 'Sucuri', pattern: /\bsucuri\b/i },
  { name: 'StackPath', pattern: /\bstackpath\b/i },
  { name: 'Bunny', pattern: /\bbunny(?:\.net|cdn)?\b/i },
  { name: 'Edgio', pattern: /\bedgio\b/i },
  { name: 'Vercel', pattern: /\bvercel\b/i },
  { name: 'Netlify', pattern: /\bnetlify\b/i },
  { name: 'Google Cloud CDN', pattern: /\bgoogle cloud cdn\b/i },
]

function publicResolver() {
  const resolver = new dns.promises.Resolver({ timeout: 5000, tries: 1 })
  resolver.setServers(['1.1.1.1', '8.8.8.8'])
  return resolver
}

export async function reverseDns(ip, { resolver = publicResolver() } = {}) {
  try {
    const names = await resolver.reverse(ip)
    return Array.isArray(names) ? names : []
  } catch {
    return []
  }
}

export function detectCdn(org) {
  const text = String(org ?? '')
  for (const { name, pattern } of CDN_PROVIDERS) {
    if (pattern.test(text)) return { is_cdn: true, cdn_provider: name }
  }
  return { is_cdn: false, cdn_provider: null }
}

export function locationAccuracy(data) {
  if (data?.city) return 'city'
  if (data?.region) return 'region'
  if (data?.country) return 'country'
  return null
}

function vcardValue(entity, key) {
  const vcard = entity?.vcardArray?.[1] ?? []
  return vcard.find((entry) => entry[0] === key)?.[3] ?? null
}

export function abuseContactFromRdap(data) {
  const entities = data?.entities ?? []
  for (const entity of entities) {
    if (!(entity.roles ?? []).includes('abuse')) continue
    const email = vcardValue(entity, 'email')
    const phone = vcardValue(entity, 'tel')
    if (email || phone) return { email: email ?? null, phone: phone ?? null }
  }
  return null
}

function cidrFromRdap(data) {
  const entry = (data?.cidr0_cidrs ?? [])[0]
  if (!entry) return null
  if (entry.v4prefix) return `${entry.v4prefix}/${entry.length}`
  if (entry.v6prefix) return `${entry.v6prefix}/${entry.length}`
  return null
}

function orgFromRdap(data) {
  for (const entity of data?.entities ?? []) {
    const roles = entity.roles ?? []
    if (!roles.includes('registrant') && !roles.includes('administrative')) continue
    const name = vcardValue(entity, 'fn') ?? vcardValue(entity, 'org')
    if (name) return name
  }
  return null
}

export function networkFromRdap(data) {
  if (!data) return null
  return {
    netname: data.name ?? null,
    cidr: cidrFromRdap(data),
    handle: data.handle ?? null,
    start: data.startAddress ?? null,
    end: data.endAddress ?? null,
    org: orgFromRdap(data),
  }
}

export async function rdapDetails(ip, {
  query = queryIp,
  getCached = cacheGet,
  setCached = cacheSet,
} = {}) {
  const cached = await getCached(RDAP_CACHE_NAME, ip)
  if (cached) return cached
  try {
    const result = await query(ip)
    if (!result?.found) return { abuse_contact: null, network: null, error: null }
    const details = {
      abuse_contact: abuseContactFromRdap(result.data),
      network: networkFromRdap(result.data),
      error: null,
    }
    await setCached(RDAP_CACHE_NAME, ip, details, RDAP_CACHE_TTL_SEC)
    return details
  } catch {
    return { abuse_contact: null, network: null, error: 'RDAP lookup failed' }
  }
}

export async function rdapAbuse(ip, options = {}) {
  return (await rdapDetails(ip, options)).abuse_contact
}

export async function enrich(ip, { resolver, query } = {}) {
  const [names, details] = await Promise.all([
    reverseDns(ip, resolver ? { resolver } : undefined),
    rdapDetails(ip, query ? { query } : undefined),
  ])
  return {
    reverse_dns: names,
    abuse_contact: details.abuse_contact,
    network: details.network,
    rdap_error: details.error,
  }
}

export function addressInCidr(address, cidr) {
  try {
    const [network, bits] = ipaddr.parseCIDR(cidr)
    return ipaddr.parse(address).match(network, bits)
  } catch {
    return false
  }
}
