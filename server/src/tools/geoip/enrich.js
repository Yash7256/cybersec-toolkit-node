import dns from 'node:dns'
import { queryIp } from '../../net/rdapClient.js'

const CDN_PATTERNS = [
  /cloudflare/i,
  /akamai/i,
  /fastly/i,
  /cloudfront/i,
  /google llc/i,
  /microsoft corporation/i,
  /azure/i,
  /imperva/i,
  /incapsula/i,
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
  return CDN_PATTERNS.some((pattern) => pattern.test(text))
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
