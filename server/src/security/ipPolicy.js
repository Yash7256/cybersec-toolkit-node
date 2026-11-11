import ipaddr from 'ipaddr.js'

// Sources (checked 2026-11-11):
// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml

const IPV4_DENY = [
  ['169.254.169.254/32', 'metadata'], // cloud metadata before generic link-local
  ['0.0.0.0/8', 'unspecified'],
  ['10.0.0.0/8', 'private'],
  ['100.64.0.0/10', 'cgnat'],
  ['127.0.0.0/8', 'loopback'],
  ['169.254.0.0/16', 'link_local'],
  ['172.16.0.0/12', 'private'],
  ['192.0.0.0/24', 'reserved'],
  ['192.0.2.0/24', 'documentation'],
  ['192.88.99.0/24', 'reserved'],
  ['192.168.0.0/16', 'private'],
  ['198.18.0.0/15', 'reserved'],
  ['198.51.100.0/24', 'documentation'],
  ['203.0.113.0/24', 'documentation'],
  ['224.0.0.0/4', 'multicast'],
  ['240.0.0.0/4', 'reserved'], // includes 255.255.255.255
].map(([cidr, reason]) => [ipaddr.parseCIDR(cidr), reason])

const IPV6_DENY = [
  ['fd00:ec2::254/128', 'metadata'], // AWS IMDS over IPv6
  ['::/128', 'unspecified'],
  ['::1/128', 'loopback'],
  ['64:ff9b:1::/48', 'translation'], // local-use NAT64
  ['100::/64', 'reserved'], // discard-only
  ['2001::/32', 'reserved'], // Teredo
  ['2001:db8::/32', 'documentation'],
  ['2001:10::/28', 'reserved'], // ORCHID
  ['3fff::/20', 'documentation'],
  ['fc00::/7', 'private'],
  ['fe80::/10', 'link_local'],
  ['fec0::/10', 'reserved'], // deprecated site-local
  ['ff00::/8', 'multicast'],
].map(([cidr, reason]) => [ipaddr.parseCIDR(cidr), reason])

const IPV4_TRANSLATED = ipaddr.parseCIDR('::ffff:0:0:0/96')
const NAT64 = ipaddr.parseCIDR('64:ff9b::/96')
const SIX_TO_FOUR = ipaddr.parseCIDR('2002::/16')
const IPV4_COMPATIBLE = ipaddr.parseCIDR('::/96')

function denyReason(address, ranges) {
  for (const [range, reason] of ranges) {
    if (address.match(range)) return reason
  }
  return null
}

function ipv4FromPair(high, low) {
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`
}

function result(allowed, reason, normalized, family) {
  return { allowed, reason, normalized, family }
}

export function classifyIp(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 45) {
    return result(false, 'malformed', null, null)
  }
  if (/\s/.test(input) || input.includes('%')) {
    return result(false, 'malformed', null, null)
  }

  let address
  try {
    address = ipaddr.parse(input)
  } catch {
    return result(false, 'malformed', null, null)
  }

  const normalized = address.toString()

  if (address.kind() === 'ipv4') {
    // ipaddr.js accepts legacy numeric forms (decimal, hex, octal, 127.1).
    // Only canonical dotted-decimal reaches policy and the resolver.
    if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(input)) {
      return result(false, 'malformed', null, null)
    }
    const reason = denyReason(address, IPV4_DENY)
    return result(reason === null, reason, normalized, 4)
  }

  const parts = address.parts

  if (normalized === '::') return result(false, 'unspecified', normalized, 6)
  if (normalized === '::1') return result(false, 'loopback', normalized, 6)

  // Unwrap IPv4 embedded in IPv6 and re-check it first. A public embedded
  // address does not make a private wrapper safe, and vice versa.
  let embedded = null
  if (address.isIPv4MappedAddress()) {
    embedded = address.toIPv4Address().toString()
  } else if (address.match(IPV4_TRANSLATED)) {
    embedded = ipv4FromPair(parts[6], parts[7])
  } else if (address.match(NAT64)) {
    embedded = ipv4FromPair(parts[6], parts[7])
  } else if (address.match(SIX_TO_FOUR)) {
    embedded = ipv4FromPair(parts[1], parts[2])
  } else if (address.match(IPV4_COMPATIBLE)) {
    embedded = ipv4FromPair(parts[6], parts[7])
  }

  if (embedded !== null) {
    const inner = classifyIp(embedded)
    if (!inner.allowed) return result(false, inner.reason, normalized, 6)
  }

  const reason = denyReason(address, IPV6_DENY)
  return result(reason === null, reason, normalized, 6)
}
