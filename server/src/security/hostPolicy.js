import net from 'node:net'
import { domainToASCII } from 'node:url'
import AppError from '../utils/AppError.js'

const BLOCKED_NAMES = new Set(['localhost', 'intranet'])
const BLOCKED_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.localdomain',
  '.lan',
  '.home.arpa',
  '.corp',
  '.intranet',
]

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

function fail(code) {
  const messages = {
    TARGET_INVALID: 'Target is invalid.',
    TARGET_AMBIGUOUS: 'Target is ambiguous.',
    TARGET_BLOCKED: 'This target is not allowed.',
  }
  throw new AppError(422, code, messages[code])
}

function looksAmbiguousNumeric(host) {
  if (/^\d+$/.test(host)) return true
  if (/^0x[0-9a-f]+$/i.test(host)) return true
  if (/^[0-9a-fx.]+$/i.test(host) && host.includes('.') && /\d/.test(host)) {
    return net.isIP(host) === 0
  }
  return false
}

function isBlockedName(host) {
  if (BLOCKED_NAMES.has(host)) return true
  return BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))
}

export function normalizeHost(input) {
  if (typeof input !== 'string' || input.length === 0) fail('TARGET_INVALID')

  // Reject control characters before trimming so "example.com\n" cannot slip
  // through, then trim ordinary surrounding whitespace.
  if (/[\u0000-\u001f\u007f]/.test(input)) fail('TARGET_INVALID')

  let host = input.trim()
  if (host.length === 0) fail('TARGET_INVALID')
  if (/\s/.test(host)) fail('TARGET_INVALID')
  if (/[@/\\?#%]/.test(host)) fail('TARGET_INVALID')

  // Bracketed IPv6 is an IP, never a hostname. Ports are a separate field.
  if (host.startsWith('[')) {
    if (!host.endsWith(']') || host.length < 3) fail('TARGET_INVALID')
    const inner = host.slice(1, -1)
    if (inner.includes('[') || inner.includes(']') || net.isIP(inner) !== 6) {
      fail('TARGET_INVALID')
    }
    return { kind: 'ip', value: inner.toLowerCase() }
  }

  // Any remaining colon is a port, a bare IPv6, or a scheme. All rejected.
  if (host.includes(':')) fail('TARGET_INVALID')

  // Exactly one trailing dot is tolerated (FQDN form).
  if (host.endsWith('.')) host = host.slice(0, -1)
  host = host.toLowerCase()
  if (host.length === 0) fail('TARGET_INVALID')

  // Detect legacy numeric IPv4 spellings before domainToASCII rewrites them.
  if (looksAmbiguousNumeric(host)) fail('TARGET_AMBIGUOUS')

  const hadNonAscii = /[^\x00-\x7f]/.test(host)
  let ascii
  try {
    ascii = domainToASCII(host)
  } catch {
    fail('TARGET_INVALID')
  }
  if (!ascii) fail('TARGET_INVALID')

  if (net.isIP(ascii) !== 0) {
    // A Unicode spelling that collapses to an IP is a parser-confusion probe.
    if (hadNonAscii) fail('TARGET_AMBIGUOUS')
    return { kind: 'ip', value: ascii }
  }

  if (ascii.length > 253) fail('TARGET_INVALID')
  if (!ascii.includes('.')) fail('TARGET_BLOCKED')
  if (isBlockedName(ascii)) fail('TARGET_BLOCKED')

  const labels = ascii.split('.')
  for (const label of labels) {
    if (!LABEL.test(label)) fail('TARGET_INVALID')
  }

  return { kind: 'host', value: ascii }
}
