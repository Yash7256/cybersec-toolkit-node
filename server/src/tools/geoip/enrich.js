import dns from 'node:dns'
import { queryIp } from '../../net/rdapClient.js'

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

export async function rdapAbuse(ip, { query = queryIp } = {}) {
  try {
    const result = await query(ip)
    if (!result?.found) return null
    const entities = result.data?.entities ?? []
    for (const entity of entities) {
      if (!(entity.roles ?? []).includes('abuse')) continue
      const vcard = entity.vcardArray?.[1] ?? []
      const email = vcard.find((entry) => entry[0] === 'email')?.[3]
      const phone = vcard.find((entry) => entry[0] === 'tel')?.[3]
      if (email || phone) return { email: email ?? null, phone: phone ?? null }
    }
    return null
  } catch {
    return null
  }
}

export async function enrich(ip, { resolver, query } = {}) {
  const [names, abuse] = await Promise.all([
    reverseDns(ip, resolver ? { resolver } : undefined),
    rdapAbuse(ip, query ? { query } : undefined),
  ])
  return {
    reverse_dns: names,
    abuse_contact: abuse,
  }
}
