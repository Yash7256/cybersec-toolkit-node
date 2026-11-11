import dns from 'node:dns'
import AppError from '../utils/AppError.js'
import { classifyIp } from './ipPolicy.js'

const MAX_ADDRESSES = 16
const PRIVATE_REASONS = new Set(['private', 'loopback', 'link_local', 'cgnat', 'metadata'])

function blocked(reason) {
  const err = new AppError(422, 'TARGET_BLOCKED', 'This target is not allowed.')
  // Internal only: the error handler serializes code/message/details, never this.
  Object.defineProperty(err, 'reason', { value: reason, enumerable: false })
  return err
}

function unresolvable() {
  return new AppError(422, 'TARGET_UNRESOLVABLE', 'Target could not be resolved.')
}

function withTimeout(promise, timeoutMs) {
  let timer
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(unresolvable()), timeoutMs)
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

// Development-only escape hatch: never populated from request input.
export function classifyAddress(value, { allowPrivate = false } = {}) {
  const result = classifyIp(value)
  if (result.allowed) return { address: result.normalized, family: result.family }
  if (allowPrivate && PRIVATE_REASONS.has(result.reason)) {
    return { address: result.normalized, family: result.family }
  }
  throw blocked(result.reason)
}

export async function resolveTarget(
  value,
  { kind, timeoutMs = 3000, allowPrivate = false, lookup = dns.promises.lookup } = {}
) {
  if (kind === 'ip') {
    const address = classifyAddress(value, { allowPrivate })
    return { host: address.address, addresses: [address] }
  }

  let answers
  try {
    answers = await withTimeout(lookup(value, { all: true, verbatim: true }), timeoutMs)
  } catch (err) {
    if (err instanceof AppError) throw err
    throw unresolvable()
  }

  if (!Array.isArray(answers) || answers.length === 0) throw unresolvable()

  const seen = new Set()
  const unique = []
  for (const answer of answers) {
    if (!answer || typeof answer.address !== 'string') continue
    if (seen.has(answer.address)) continue
    seen.add(answer.address)
    unique.push(answer)
    if (unique.length === MAX_ADDRESSES) break
  }
  if (unique.length === 0) throw unresolvable()

  const addresses = []
  for (const answer of unique) {
    addresses.push(classifyAddress(answer.address, { allowPrivate }))
  }

  return { host: value, addresses }
}

// net.connect/tls.connect lookup signature. Answers only from the validated
// list and never touches DNS, so a second resolver answer cannot be swapped in.
export function pinnedLookup(addresses) {
  const list = addresses.map(({ address, family }) => ({ address, family }))

  return function lookup(_hostname, options, callback) {
    let opts = options
    let cb = callback
    if (typeof options === 'function') {
      cb = options
      opts = {}
    }
    if (typeof opts === 'number') opts = { family: opts }
    opts = opts || {}

    const candidates =
      opts.family === 4 || opts.family === 6
        ? list.filter((entry) => entry.family === opts.family)
        : list

    if (opts.all) {
      process.nextTick(() => cb(null, candidates))
      return
    }

    if (candidates.length === 0) {
      const err = new Error('no validated address for requested family')
      err.code = 'ENOTFOUND'
      process.nextTick(() => cb(err))
      return
    }

    const chosen = candidates[0]
    process.nextTick(() => cb(null, chosen.address, chosen.family))
  }
}
