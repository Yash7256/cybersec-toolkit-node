import dns from 'node:dns'
import AppError from '../utils/AppError.js'
import { classifyIp } from './ipPolicy.js'

const MAX_ADDRESSES = 16

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

export async function resolveTarget(
  value,
  { kind, timeoutMs = 3000, lookup = dns.promises.lookup } = {}
) {
  if (kind === 'ip') {
    const result = classifyIp(value)
    if (!result.allowed) throw blocked(result.reason)
    return {
      host: result.normalized,
      addresses: [{ address: result.normalized, family: result.family }],
    }
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
    const result = classifyIp(answer.address)
    if (!result.allowed) throw blocked(result.reason)
    addresses.push({ address: result.normalized, family: result.family })
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
