import crypto from 'node:crypto'
import { queryAll, TYPE_NUMBERS } from '../../net/dohClient.js'
import { env as defaultEnv } from '../../config/env.js'

export function randomPrefix(length = 10) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz'
  const bytes = crypto.randomBytes(length)
  let out = ''
  for (let index = 0; index < length; index += 1) {
    out += alphabet[bytes[index] % alphabet.length]
  }
  return out
}

function aRecords(body) {
  const answers = Array.isArray(body?.Answer) ? body.Answer : []
  return answers
    .filter((answer) => Number(answer?.type) === TYPE_NUMBERS.A)
    .map((answer) => String(answer.data ?? '').trim().replace(/\.$/, ''))
    .filter(Boolean)
}

export async function detectWildcard(domain, {
  env = defaultEnv,
  query = queryAll,
  prefix = randomPrefix,
  checks = env.SUBDOMAIN_WILDCARD_CHECKS,
  signal,
} = {}) {
  const attempts = Array.from({ length: checks }, async () => {
    if (signal?.aborted) return []
    const hostname = `${prefix()}.${domain}`
    try {
      const [result] = await query(hostname, ['A'], { overallMs: env.SUBDOMAIN_HTTP_TIMEOUT_MS })
      if (result?.error || Number(result?.data?.Status ?? 0) !== 0) return []
      return aRecords(result.data)
    } catch {
      return []
    }
  })

  const ips = new Set()
  for (const found of await Promise.all(attempts)) {
    for (const ip of found) ips.add(ip)
  }
  return { detected: ips.size > 0, ips: [...ips] }
}

export function markWildcardEntries(results, wildcardIps, strictness = 'medium') {
  if (wildcardIps.length === 0) return results
  const wildcard = new Set(wildcardIps)
  for (const entry of results) {
    if (!entry?.resolved) continue
    const match = new Set(entry.records?.A ?? [])
    if (strictness === 'high') {
      for (const ip of entry.records?.AAAA ?? []) match.add(ip)
    }
    if ([...match].some((ip) => wildcard.has(ip))) entry.wildcard = true
  }
  return results
}
