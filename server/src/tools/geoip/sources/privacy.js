function boolOrNull(value) {
  return typeof value === 'boolean' ? value : null
}

const USAGE_TYPE_MAP = [
  [/data ?cent(er|re)|hosting|cloud|colo/i, 'hosting'],
  [/mobile/i, 'mobile'],
  [/fixed line|residential|isp/i, 'residential'],
  [/university|college|school|education/i, 'education'],
  [/government|military/i, 'government'],
  [/commercial|business|enterprise/i, 'business'],
]

export function classifyUsageType(usageType) {
  if (!usageType) return null
  for (const [pattern, value] of USAGE_TYPE_MAP) {
    if (pattern.test(usageType)) return value
  }
  return null
}

export function buildPrivacy({ providerPrivacy, torStatus, hosting, usageType } = {}) {
  const sources = []
  const privacy = {
    vpn: boolOrNull(providerPrivacy?.vpn),
    proxy: boolOrNull(providerPrivacy?.proxy),
    tor: boolOrNull(providerPrivacy?.tor),
    relay: boolOrNull(providerPrivacy?.relay),
    hosting: boolOrNull(providerPrivacy?.hosting),
  }
  if (providerPrivacy) sources.push('provider')

  if (torStatus !== null && torStatus !== undefined) {
    privacy.tor = Boolean(torStatus)
    sources.push('tor-exit-list')
  }
  if (hosting !== null && hosting !== undefined) {
    privacy.hosting = Boolean(hosting)
    sources.push('asn-list')
  }

  let ipType = null
  let basis = null
  if (privacy.tor === true) {
    ipType = 'tor'
    basis = 'tor-exit-list'
  } else if (privacy.vpn === true) {
    ipType = 'vpn'
    basis = 'provider-privacy'
  } else if (privacy.proxy === true) {
    ipType = 'proxy'
    basis = 'provider-privacy'
  } else if (privacy.relay === true) {
    ipType = 'relay'
    basis = 'provider-privacy'
  } else if (privacy.hosting === true) {
    ipType = 'hosting'
    basis = sources.includes('asn-list') ? 'asn-list' : 'provider-privacy'
  } else {
    const usage = classifyUsageType(usageType)
    if (usage) {
      ipType = usage
      basis = 'abuseipdb-usage-type'
    }
  }

  return {
    privacy,
    privacy_sources: [...new Set(sources)],
    ip_type: ipType,
    ip_type_basis: basis,
  }
}
