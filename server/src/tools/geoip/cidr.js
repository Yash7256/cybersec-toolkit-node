import ipaddr from 'ipaddr.js'
import { z } from 'zod'
import { classifyIp } from '../../security/ipPolicy.js'
import { definition as geoipDefinition } from './index.js'
import { env as defaultEnv } from '../../config/env.js'
import AppError from '../../utils/AppError.js'

const MAX_ADDRESSES = 256

export const schema = z.object({ target: z.string().trim().min(1).max(64) })

function expandCidr(cidr) {
  let network
  let bits
  try {
    ;[network, bits] = ipaddr.parseCIDR(cidr)
  } catch {
    throw new AppError(422, 'VALIDATION_ERROR', 'Invalid CIDR block')
  }
  const kind = network.kind()
  if (kind === 'ipv4' && (bits < 24 || bits > 32)) {
    throw new AppError(422, 'VALIDATION_ERROR', 'IPv4 CIDR must be between /24 and /32')
  }
  if (kind === 'ipv6' && (bits < 120 || bits > 128)) {
    throw new AppError(422, 'VALIDATION_ERROR', 'IPv6 CIDR must be between /120 and /128')
  }
  const maxBits = kind === 'ipv4' ? 32 : 128
  const count = 2 ** (maxBits - bits)
  if (count > MAX_ADDRESSES) {
    throw new AppError(422, 'VALIDATION_ERROR', `CIDR expands to more than ${MAX_ADDRESSES} addresses`)
  }
  const bytes = network.toByteArray()
  let base = 0n
  for (const byte of bytes) base = (base << 8n) | BigInt(byte)
  const addresses = []
  for (let index = 0; index < count; index += 1) {
    let value = base + BigInt(index)
    const out = new Array(bytes.length)
    for (let i = bytes.length - 1; i >= 0; i -= 1) {
      out[i] = Number(value & 0xffn)
      value >>= 8n
    }
    addresses.push(ipaddr.fromByteArray(out).toString())
  }
  return { addresses, cidr: `${network.toString()}/${bits}` }
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length)
  let next = 0
  async function worker() {
    while (next < items.length) {
      const index = next
      next += 1
      results[index] = await fn(items[index], index)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return results
}

export function emptyResult(input) {
  return {
    target: input?.target ?? null,
    mode: 'cidr',
    total: 0,
    completed: 0,
    failed: 0,
    skipped: [],
    summary: { countries: {}, asns: {}, ip_types: {}, cdn: 0, hosting: 0, tor: 0 },
    ip_results: [],
    results: [],
    warnings: [],
    error: null,
  }
}

export function createCidrDefinition({
  geoip = geoipDefinition,
  env = defaultEnv,
  lookup = (address, ctx) => geoip.execute({ target: address }, ctx),
} = {}) {
  return {
    name: 'geoip_cidr',
    toolEnum: 'GEOIP_CIDR',
    schema,
    touchesTarget: false,
    dedupeTtlSec: 0,
    mode: 'auto',
    asyncWhen: (input) => (input.addresses?.length ?? 0) > 16,
    normalize: (input) => ({ ...input, target: input.target.trim() }),
    validateInput: (input) => {
      const expanded = expandCidr(input.target)
      const skipped = []
      const addresses = []
      for (const address of expanded.addresses) {
        const classified = classifyIp(address)
        if (classified.allowed) addresses.push(address)
        else skipped.push({ ip: address, reason: classified.reason })
      }
      if (addresses.length === 0) {
        throw new AppError(422, 'TARGET_BLOCKED', 'This CIDR contains no public addresses')
      }
      input.addresses = addresses
      input.skipped = skipped
      return { targetKey: expanded.cidr.toLowerCase(), addresses: [], display: expanded.cidr }
    },
    async execute(input, ctx) {
      const addresses = input.addresses ?? []
      const outcomes = await mapLimit(addresses, 4, async (address, index) => {
        if (ctx?.signal?.aborted) throw new AppError(504, 'TOOL_TIMEOUT', 'Request timed out')
        try {
          const data = await lookup(address, ctx)
          ctx?.reportProgress?.(Math.round(((index + 1) / addresses.length) * 100))
          return { ip: address, status: 'ok', data }
        } catch (err) {
          return { ip: address, status: 'error', error: err?.message ?? 'Lookup failed' }
        }
      })
      const ok = outcomes.filter((row) => row.status === 'ok')
      const summary = { countries: {}, asns: {}, ip_types: {}, cdn: 0, hosting: 0, tor: 0 }
      for (const row of ok) {
        const data = row.data
        if (data.country_code) summary.countries[data.country_code] = (summary.countries[data.country_code] ?? 0) + 1
        if (data.asn) summary.asns[data.asn] = (summary.asns[data.asn] ?? 0) + 1
        if (data.ip_type) summary.ip_types[data.ip_type] = (summary.ip_types[data.ip_type] ?? 0) + 1
        if (data.is_cdn) summary.cdn += 1
        if (data.privacy?.hosting) summary.hosting += 1
        if (data.privacy?.tor) summary.tor += 1
      }
      return {
        ...emptyResult(input),
        target: input.target,
        total: addresses.length,
        completed: ok.length,
        failed: outcomes.length - ok.length,
        skipped: input.skipped ?? [],
        summary,
        ip_results: ok.flatMap((row) => row.data.ip_results ?? []),
        results: outcomes.map((row) => row.status === 'ok'
          ? {
              ip: row.ip,
              status: 'ok',
              country_code: row.data.country_code ?? null,
              city: row.data.city ?? null,
              asn: row.data.asn ?? null,
              org: row.data.org ?? null,
              ip_type: row.data.ip_type ?? null,
            }
          : { ip: row.ip, status: 'error', error: row.error }),
        warnings: [...new Set(ok.flatMap((row) => (row.data.warnings ?? []).map((warning) => warning.source)))].map((source) => ({ source, message: 'Source unavailable' })),
      }
    },
    emptyResult,
    summarize: (data) => ({ total: data.total, completed: data.completed, failed: data.failed }),
  }
}

export const definition = createCidrDefinition()
