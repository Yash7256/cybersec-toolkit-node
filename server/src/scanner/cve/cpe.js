export const SERVICE_CPE_MAPPINGS = {
  apache: 'apache',
  nginx: 'nginx',
  openssh: 'openssh',
  ssh: 'openssh',
  mysql: 'mysql',
  postgresql: 'postgresql',
  postgres: 'postgresql',
  redis: 'redis',
  mongodb: 'mongodb',
  tomcat: 'apache_tomcat',
  jetty: 'jetty',
  lighttpd: 'lighttpd',
  iis: 'microsoft_iis',
  ftp: 'ftp',
  vsftpd: 'vsftpd',
  proftpd: 'proftpd',
  smtp: 'smtp',
  sendmail: 'sendmail',
  postfix: 'postfix',
  exim: 'exim',
  dovecot: 'dovecot',
  bind: 'bind',
  dns: 'bind',
  openssl: 'openssl',
  libssl: 'openssl',
  php: 'php',
  'node.js': 'node.js',
}

const VERSION_PATTERNS = [
  /^([a-zA-Z][a-zA-Z0-9_.-]*)[/\s]+([0-9][0-9.]*[a-zA-Z0-9.-]*)/,
  /^([a-zA-Z][a-zA-Z0-9_.-]*)(?:[_-])([0-9][0-9.]*[a-zA-Z0-9.-]*)/,
]

export function normalizeServiceName(service) {
  return SERVICE_CPE_MAPPINGS[String(service).toLowerCase().trim()] ?? String(service).toLowerCase().trim()
}

export function parseVersionString(versionString) {
  if (!versionString) return null
  const input = String(versionString).trim()

  const iis = /^microsoft\s+iis\s+([0-9][0-9.]*[a-zA-Z0-9.-]*)/i.exec(input)
  if (iis) {
    return [normalizeServiceName('iis'), iis[1].replace(/[^0-9.].*$/, '')]
  }

  for (const pattern of VERSION_PATTERNS) {
    const match = pattern.exec(input)
    if (!match) continue
    const version = match[2].replace(/[^0-9.].*$/, '')
    if (version) return [normalizeServiceName(match[1]), version]
  }

  return null
}

// A banner can combine several products ("Apache 2.4.49, PHP 7.4.3"). The old
// code parsed only the first; the batch helper intentionally expands all of
// them and merges the results under the original key.
export function parseVersionStrings(versionString) {
  if (!versionString) return []
  const input = String(versionString).trim()
  if (!input) return []

  const parts = input.split(',').map((part) => part.trim()).filter(Boolean)
  const parsed = []
  const seen = new Set()
  for (const part of parts.length > 1 ? parts : [input]) {
    const item = parseVersionString(part)
    if (!item) continue
    const key = item.join('|')
    if (seen.has(key)) continue
    seen.add(key)
    parsed.push(item)
  }
  return parsed
}

export function cvssScoreToSeverity(score) {
  if (score == null) return 'UNKNOWN'
  if (score >= 9.0) return 'CRITICAL'
  if (score >= 7.0) return 'HIGH'
  if (score >= 4.0) return 'MEDIUM'
  if (score > 0) return 'LOW'
  return 'NONE'
}

const CPE_VENDOR_PRODUCT = {
  apache: ['apache', 'http_server'],
  apache_tomcat: ['apache', 'tomcat'],
  openssh: ['openbsd', 'openssh'],
  microsoft_iis: ['microsoft', 'internet_information_services'],
  mysql: ['oracle', 'mysql'],
  postgresql: ['postgresql', 'postgresql'],
  redis: ['redis', 'redis'],
  mongodb: ['mongodb', 'mongodb'],
}

export function cpeFor(service, version) {
  const product = normalizeServiceName(service)
  const [vendor, name] = CPE_VENDOR_PRODUCT[product] ?? [product, product]
  return `cpe:2.3:a:${vendor}:${name}:${version}:*:*:*:*:*:*:*`
}
