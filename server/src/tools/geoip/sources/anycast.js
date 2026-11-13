import ipaddr from 'ipaddr.js'

const ANYCAST_PREFIXES = [
  '1.1.1.0/24',
  '1.0.0.0/24',
  '8.8.8.0/24',
  '8.8.4.0/24',
  '9.9.9.0/24',
  '149.112.112.0/24',
  '208.67.222.0/24',
  '208.67.220.0/24',
  '2606:4700:4700::/48',
  '2001:4860:4860::/48',
  '2620:fe::/48',
]

const ANYCAST_ASNS = new Set(['AS13335', 'AS15169', 'AS19281', 'AS36692'])

export function detectAnycast({ ip, asn } = {}) {
  if (ip) {
    try {
      const parsed = ipaddr.parse(ip)
      for (const cidr of ANYCAST_PREFIXES) {
        const [network, bits] = ipaddr.parseCIDR(cidr)
        if (parsed.kind() === network.kind() && parsed.match(network, bits)) {
          return { likely: true, basis: `curated-prefix:${cidr}` }
        }
      }
    } catch {}
  }
  if (asn && ANYCAST_ASNS.has(String(asn).toUpperCase())) {
    return { likely: true, basis: `curated-asn:${String(asn).toUpperCase()}` }
  }
  return { likely: null, basis: null }
}
