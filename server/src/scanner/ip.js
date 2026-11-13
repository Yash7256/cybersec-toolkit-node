import ipaddr from 'ipaddr.js'

const PUBLIC_RANGE = 'unicast'

export function parseIp(value) {
  if (!value || typeof value !== 'string') return null
  try {
    return ipaddr.parse(value)
  } catch {
    return null
  }
}

export function isPublicIp(value) {
  const parsed = parseIp(value)
  if (!parsed) return false
  if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
    return parsed.toIPv4Address().range() === PUBLIC_RANGE
  }
  return parsed.range() === PUBLIC_RANGE
}
