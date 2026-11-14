import { createHash } from 'node:crypto'
import { classifyIp } from '../../security/ipPolicy.js'
import AppError from '../../utils/AppError.js'
import { classifyInput, expandCidr } from './classify.js'

function tierMax(tier, env) {
  const paid = tier === 'PAID' || tier === 'ADMIN'
  const configured = paid ? env.GEOIP_MAX_UNITS_PAID : env.GEOIP_MAX_UNITS_FREE
  const legacy = paid ? env.GEOIP_BULK_MAX_PAID : env.GEOIP_BULK_MAX_FREE
  return Number(configured ?? legacy ?? (paid ? 100 : 10))
}

function reject(token, reason = token.reason) { return { input: token.raw, reason: reason || 'invalid target' } }

export function buildPlan(raw, { tier = 'FREE', env = {} } = {}) {
  const { tokens } = classifyInput(raw, { maxChars: 20000, maxTokens: 500 })
  const rejected = tokens.filter((token) => token.kind === 'invalid').map((token) => reject(token))
  const skipped = []
  const expanded_from = []
  const units = []
  const seen = new Set()

  for (const token of tokens) {
    if (token.kind === 'invalid') continue
    if (token.kind === 'cidr') {
      const expanded = expandCidr(token.canonical)
      expanded_from.push({ input: token.raw, cidr: expanded.cidr, count: expanded.addresses.length })
      for (let index = 0; index < expanded.addresses.length; index += 1) {
        const address = expanded.addresses[index]
        if (expanded.family === 'ipv4' && expanded.prefix <= 30 && (index === 0 || index === expanded.addresses.length - 1)) {
          skipped.push({ input: address, reason: index === 0 ? 'network address' : 'broadcast address' })
          continue
        }
        const policy = classifyIp(address)
        if (!policy.allowed) { skipped.push({ input: address, reason: policy.reason }); continue }
        if (!seen.has(`ip:${policy.normalized}`)) {
          seen.add(`ip:${policy.normalized}`)
          units.push({ input: address, canonical: policy.normalized, kind: 'ip', source: token.raw })
        }
      }
      continue
    }
    const kind = token.kind === 'ipv4' || token.kind === 'ipv6' ? 'ip' : token.kind
    const key = `${kind}:${token.canonical}`
    if (!seen.has(key)) { seen.add(key); units.push({ input: token.raw, canonical: token.canonical, kind }) }
  }

  if (units.length === 0) throw new AppError(422, 'VALIDATION_ERROR', 'No valid target remains', { rejected, skipped })
  const max = tierMax(tier, env)
  if (units.length > max) throw new AppError(422, 'VALIDATION_ERROR', `GeoIP lookup is limited to ${max} units on your plan`, { max, received: units.length, rejected, skipped })

  const mode = units.length === 1 && units[0].kind === 'asn' ? 'asn' : units.length === 1 ? 'single' : 'batch'
  const targetKey = mode === 'single' ? units[0].canonical : mode === 'asn' ? units[0].canonical.toLowerCase() : createHash('sha256').update(tokens.filter((token) => token.kind !== 'invalid').map((token) => token.canonical).sort().join('\n')).digest('hex')
  return { mode, tokens, units: units.length, items: units, unitsCount: units.length, rejected, skipped, expanded_from, targetKey, display: mode === 'batch' ? `GeoIP (${units.length})` : units[0].input }
}
