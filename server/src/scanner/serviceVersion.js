const OPENSSH_RE = /OpenSSH[_\s]([\d.p\w.-]+)/i
const APACHE_RE = /Apache[/\s]([\d.]+)/i
const NGINX_RE = /nginx[/\s]([\d.]+)/i
const PHP_RE = /PHP[/\s]([\d.]+)/i
const IIS_RE = /Microsoft-IIS[/\s]([\d.]+)/i
const NODE_RE = /(?:Node\.js[/\s]([\d.]+)|Express(?:[/\s]([\d.]+))?|(?:^|[\s,])Node(?:[/\s]([\d.]+))?)/i

function toText(input) {
  if (input == null) return ''
  return Buffer.isBuffer(input) ? input.toString('utf8') : String(input)
}

export function parseSshBanner(banner) {
  const match = OPENSSH_RE.exec(toText(banner))
  return match ? `OpenSSH ${match[1]}` : null
}

export function extractHttpVersions(headerValue) {
  const value = toText(headerValue)
  const found = []

  for (const [pattern, label] of [
    [APACHE_RE, 'Apache'],
    [NGINX_RE, 'nginx'],
    [IIS_RE, 'IIS'],
    [PHP_RE, 'PHP'],
  ]) {
    const match = pattern.exec(value)
    if (match) found.push(`${label} ${match[1]}`)
  }

  const nodeMatch = NODE_RE.exec(value)
  if (nodeMatch) {
    const version = nodeMatch[1] || nodeMatch[2] || nodeMatch[3]
    if (version) found.push(`Node.js ${version}`)
    else if (value.toLowerCase().includes('express')) found.push('Express')
    else found.push('Node.js')
  }

  return found
}

export function parseHttpResponse(raw) {
  const text = toText(raw)
  const headerBlock = text.split(/\r?\n\r?\n/, 1)[0]
  const versions = []

  for (const line of headerBlock.split(/\r?\n/)) {
    if (!line.includes(':')) continue
    const index = line.indexOf(':')
    const name = line.slice(0, index).trim().toLowerCase()
    if (name !== 'server' && name !== 'x-powered-by') continue
    versions.push(...extractHttpVersions(line.slice(index + 1).trim()))
  }

  return versions.length > 0 ? versions.join(', ') : null
}

export const _extractHttpVersions = extractHttpVersions
