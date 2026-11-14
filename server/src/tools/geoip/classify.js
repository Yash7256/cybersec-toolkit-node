import ipaddr from 'ipaddr.js'
import net from 'node:net'
import { normalizeHost } from '../../security/hostPolicy.js'
import { classifyIp } from '../../security/ipPolicy.js'
import AppError from '../../utils/AppError.js'

const MAX_CIDR_ADDRESSES = 256
const TOKEN_RE = /[^\s,;]+/g

function invalid(raw, reason) { return { raw, kind: 'invalid', canonical: null, reason } }

function maskedAddress(address, prefix) {
  const bytes = address.toByteArray()
  let remaining = prefix
  for (let index = 0; index < bytes.length; index += 1) {
    const keep = Math.max(0, Math.min(8, remaining))
    bytes[index] &= keep === 0 ? 0 : (0xff << (8 - keep)) & 0xff
    remaining -= 8
  }
  return ipaddr.fromByteArray(bytes)
}

function normalizeEndpoint(raw) {
  let value = raw
  if (/^https?:\/\//i.test(value)) {
    try { value = new URL(value).hostname } catch { throw new AppError(422, 'VALIDATION_ERROR', 'Invalid hostname') }
  } else if (value.startsWith('[') && value.includes(']:')) {
    value = value.slice(0, value.indexOf(']:') + 1)
  } else if (net.isIP(value) === 0 && /^[^:]+:\d{1,5}$/.test(value)) {
    value = value.slice(0, value.lastIndexOf(':'))
  }
  return normalizeHost(value)
}

function parseCidr(raw) {
  if (!/^\S+\/\d{1,3}$/.test(raw)) return null
  let parsed
  try { parsed = ipaddr.parseCIDR(raw) } catch { return invalid(raw, 'invalid CIDR') }
  const [address, prefix] = parsed
  const family = address.kind()
  const min = family === 'ipv4' ? 24 : 120
  const max = family === 'ipv4' ? 32 : 128
  if (prefix < min || prefix > max) return invalid(raw, `${family === 'ipv4' ? 'IPv4' : 'IPv6'} CIDR must be between /${min} and /${max}`)
  const canonical = `${maskedAddress(address, prefix).toString()}/${prefix}`
  return { raw, kind: 'cidr', canonical, family, prefix, normalized: canonical !== raw.toLowerCase() }
}

export function classifyInput(raw, { maxChars = 20000, maxTokens = 500 } = {}) {
  if (typeof raw !== 'string') throw new AppError(422, 'VALIDATION_ERROR', 'Target must be a string')
  if (raw.length > maxChars) throw new AppError(422, 'VALIDATION_ERROR', 'Target is too long', { max: maxChars, received: raw.length })
  const values = raw.match(TOKEN_RE) ?? []
  if (values.length > maxTokens) throw new AppError(422, 'VALIDATION_ERROR', 'Too many targets', { max: maxTokens, received: values.length })
  const seen = new Set()
  const tokens = []
  for (const value of values) {
    let token
    if (/^\d+$/.test(value)) token = invalid(value, 'Did you mean AS<n>?')
    else if (/^\d+(?:\.\d+){0,3}-/.test(value) || /-/.test(value) && value.includes('.')) token = invalid(value, 'ranges not supported, use CIDR')
    else if (/^AS\d+$/i.test(value)) {
      const number = Number(value.slice(2))
      token = number >= 1 && number <= 4294967295
        ? { raw: value, kind: 'asn', canonical: `AS${number}` }
        : invalid(value, 'ASN must be between AS1 and AS4294967295')
    } else if (/^\S+\/\d{1,3}$/.test(value)) token = parseCidr(value)
    else {
      const ip = net.isIP(value)
      if (ip) {
        const policy = classifyIp(value)
        token = policy.allowed
          ? { raw: value, kind: ip === 4 ? 'ipv4' : 'ipv6', canonical: policy.normalized }
          : { raw: value, kind: 'invalid', canonical: null, reason: policy.reason }
      } else {
        try {
          const host = normalizeEndpoint(value)
          token = { raw: value, kind: host.kind, canonical: host.value }
        } catch (error) { token = invalid(value, error?.message ?? 'invalid target') }
      }
    }
    const key = token.canonical ? `${token.kind}:${token.canonical}` : `invalid:${token.raw}`
    if (!seen.has(key)) { seen.add(key); tokens.push(token) }
  }
  return { tokens }
}

export function expandCidr(cidr) {
  let network, prefix
  try { [network, prefix] = ipaddr.parseCIDR(cidr) } catch { throw new AppError(422, 'VALIDATION_ERROR', 'Invalid CIDR block') }
  network = maskedAddress(network, prefix)
  const family = network.kind()
  const bits = family === 'ipv4' ? 32 : 128
  const count = 2 ** (bits - prefix)
  if (count > MAX_CIDR_ADDRESSES) throw new AppError(422, 'VALIDATION_ERROR', `CIDR expands to more than ${MAX_CIDR_ADDRESSES} addresses`, { max: MAX_CIDR_ADDRESSES, received: count })
  const bytes = network.toByteArray()
  let base = 0n
  for (const byte of bytes) base = (base << 8n) | BigInt(byte)
  const addresses = []
  for (let offset = 0; offset < count; offset += 1) {
    let value = base + BigInt(offset)
    const out = new Array(bytes.length)
    for (let i = out.length - 1; i >= 0; i -= 1) { out[i] = Number(value & 0xffn); value >>= 8n }
    addresses.push(ipaddr.fromByteArray(out).toString())
  }
  return { addresses, cidr: `${network.toString()}/${prefix}`, family, prefix }
}

export { MAX_CIDR_ADDRESSES }
