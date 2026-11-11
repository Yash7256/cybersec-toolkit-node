import net from 'node:net'
import { z } from 'zod'
import ipaddr from 'ipaddr.js'
import AppError from '../utils/AppError.js'
import { env as defaultEnv } from '../config/env.js'
import { normalizeHost } from './hostPolicy.js'
import { classifyAddress, resolveTarget } from './resolve.js'
import { classifyIp } from './ipPolicy.js'

const MAX_TARGETS = 256
const INVALID = 'Target is invalid.'
const BLOCKED = 'This target is not allowed.'

function invalid() {
  return new AppError(422, 'TARGET_INVALID', INVALID)
}

function dotted(value) {
  return `${(value >>> 24) & 0xff}.${(value >>> 16) & 0xff}.${(value >>> 8) & 0xff}.${value & 0xff}`
}

function expandCidr(value, { allowPrivate }) {
  const slash = value.indexOf('/')
  if (slash === -1) return null

  const addressPart = value.slice(0, slash)
  const prefixPart = value.slice(slash + 1)
  if (!/^\d{1,2}$/.test(prefixPart)) throw invalid()
  if (net.isIP(addressPart) === 6) throw invalid()
  if (net.isIP(addressPart) !== 4) throw invalid()

  const prefix = Number(prefixPart)
  if (!Number.isInteger(prefix) || prefix < 24 || prefix > 32) throw invalid()

  let network
  try {
    ;[network] = ipaddr.parseCIDR(`${addressPart}/${prefix}`)
  } catch {
    throw invalid()
  }

  // Size is bounded by /24 before any allocation.
  const bytes = network.toByteArray()
  const raw = ((bytes[0] << 24) >>> 0) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]
  const mask = (0xffffffff << (32 - prefix)) >>> 0
  const start = (raw & mask) >>> 0
  const span = 2 ** (32 - prefix)

  const addresses = []
  for (let offset = 0; offset < span; offset += 1) {
    addresses.push(classifyAddress(dotted((start + offset) >>> 0), { allowPrivate }))
  }

  return {
    kind: 'cidr',
    targetKey: `${dotted(start)}/${prefix}`,
    addresses,
  }
}

function attachIndex(err, index) {
  if (err && typeof err === 'object') {
    try {
      Object.defineProperty(err, 'index', { value: index, enumerable: false })
    } catch {
      // frozen error: index is best-effort
    }
  }
  return err
}

// Small dependency-free concurrency limiter; stops scheduling after the
// first failure so a bad target cannot fan out the rest of the list.
function mapLimit(items, limit, fn) {
  const results = new Array(items.length)
  let next = 0
  let stopped = false

  async function worker() {
    while (!stopped) {
      const index = next
      next += 1
      if (index >= items.length) return
      try {
        results[index] = await fn(items[index], index)
      } catch (err) {
        stopped = true
        throw err
      }
    }
  }

  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    () => worker()
  )
  return Promise.all(workers).then(() => results)
}

async function validateOne(value, { allowPrivate, resolver }) {
  if (typeof value !== 'string') throw invalid()

  const cidr = value.includes('/') ? expandCidr(value, { allowPrivate }) : null
  if (cidr) {
    return { target: value.slice(0, 255), ...cidr }
  }

  const normalized = normalizeHost(value)
  const resolved = await resolver(normalized.value, {
    kind: normalized.kind,
    allowPrivate,
  })

  return {
    target: value.slice(0, 255),
    targetKey: resolved.host.toLowerCase(),
    kind: normalized.kind,
    addresses: resolved.addresses,
  }
}

export async function validateTarget(
  input,
  { env = defaultEnv, resolver = resolveTarget } = {}
) {
  if (typeof input !== 'string' || input.includes('/')) throw invalid()
  const allowPrivate = env.ALLOW_PRIVATE_TARGETS === true
  return validateOne(input, { allowPrivate, resolver })
}

export async function validateTargets(
  list,
  { env = defaultEnv, concurrency = 8, resolver = resolveTarget } = {}
) {
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_TARGETS) throw invalid()

  const allowPrivate = env.ALLOW_PRIVATE_TARGETS === true
  const results = await mapLimit(list, concurrency, (value, index) =>
    validateOne(value, { allowPrivate, resolver }).catch((err) => {
      throw attachIndex(err, index)
    })
  )

  const seen = new Set()
  return results.filter((result) => {
    if (seen.has(result.targetKey)) return false
    seen.add(result.targetKey)
    return true
  })
}

export const targetSchema = z.string().trim().min(1).max(260)
export const targetsSchema = z.array(targetSchema).min(1).max(MAX_TARGETS)

function urlHost(hostname) {
  if (hostname.startsWith('[')) return hostname
  return hostname.includes(':') ? `[${hostname}]` : hostname
}

export const urlTargetSchema = z
  .string()
  .trim()
  .min(1)
  .max(2048)
  .transform((value, ctx) => {
    const issue = (message = INVALID) => {
      ctx.addIssue({ code: 'custom', message })
      return z.NEVER
    }

    let parsed
    try {
      parsed = new URL(value)
    } catch {
      return issue()
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return issue()
    if (parsed.username || parsed.password) return issue()

    let normalized
    try {
      normalized = normalizeHost(urlHost(parsed.hostname))
    } catch {
      return issue()
    }

    if (normalized.kind === 'ip' && !classifyIp(normalized.value).allowed) {
      return issue(BLOCKED)
    }

    const port = parsed.port
      ? Number(parsed.port)
      : parsed.protocol === 'https:'
        ? 443
        : 80

    return { url: parsed.toString(), host: normalized.value, port }
  })

export async function validateRedirect(
  location,
  baseUrl,
  { env = defaultEnv, resolver = resolveTarget } = {}
) {
  if (typeof location !== 'string' || typeof baseUrl !== 'string') throw invalid()

  let parsed
  try {
    parsed = new URL(location, baseUrl)
  } catch {
    throw invalid()
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw invalid()
  if (parsed.username || parsed.password) throw invalid()

  const target = await validateTarget(urlHost(parsed.hostname), { env, resolver })
  return { url: parsed.toString(), ...target }
}
