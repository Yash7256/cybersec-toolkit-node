import { queryAll, TYPE_NUMBERS } from '../../net/dohClient.js'
import { env as defaultEnv } from '../../config/env.js'

export const RECORD_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'])
const TRANSIENT_MESSAGES = new Set(['Lookup service unavailable', 'Query timed out'])

function unquoteTxt(value) {
  const trimmed = String(value ?? '').trim()
  const quoted = trimmed.match(/^"([\s\S]*)"$/)
  return quoted ? quoted[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\') : trimmed
}

function extract(type, data) {
  if (type === 'TXT') return unquoteTxt(data)
  if (type === 'MX') return String(data ?? '').trim().split(/\s+/).pop() ?? ''
  return String(data ?? '').trim().replace(/\.$/, '')
}

function readAnswer(type, body) {
  const typeNumber = TYPE_NUMBERS[type]
  const answers = Array.isArray(body?.Answer) ? body.Answer : []
  const values = []
  for (const answer of answers) {
    if (Number(answer?.type) !== typeNumber) continue
    const value = extract(type, answer.data)
    if (value) values.push(value)
  }
  return values
}

export async function resolveRecordsOnce(hostname, {
  env = defaultEnv,
  query = queryAll,
} = {}) {
  const started = Date.now()
  const results = await query(hostname, RECORD_TYPES, { overallMs: env.SUBDOMAIN_HTTP_TIMEOUT_MS * 2 })
  const records = Object.fromEntries(RECORD_TYPES.map((type) => [type, []]))
  const errors = []
  let nxdomain = false

  for (const result of results) {
    if (result?.error) {
      errors.push({ type: result.type, message: result.error.message ?? 'Lookup failed' })
      continue
    }
    const status = Number(result?.data?.Status ?? 0)
    if (status === 3) {
      nxdomain = true
      continue
    }
    if (status !== 0) {
      errors.push({ type: result.type, message: 'Lookup service unavailable' })
      continue
    }
    records[result.type] = readAnswer(result.type, result.data)
  }

  const resolved = RECORD_TYPES.some((type) => records[type].length > 0)
  const result = {
    subdomain: hostname,
    records,
    resolved,
    source: ['wordlist'],
    dns_ms: Date.now() - started,
  }
  if (records.A.length > 0) result.ip = records.A[0]

  if (!resolved) {
    if (nxdomain) result.error = 'NXDOMAIN'
    else if (errors.some((entry) => TRANSIENT_MESSAGES.has(entry.message))) result.error = 'timeout'
    else result.error = 'no records'
  }
  return result
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export async function resolveSubdomainRecords(hostname, {
  env = defaultEnv,
  query = queryAll,
  signal,
  retries = 1,
  wait = sleep,
} = {}) {
  let last
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    if (signal?.aborted) throw new Error('aborted')
    last = await resolveRecordsOnce(hostname, { env, query })
    if (last.resolved || last.error === 'NXDOMAIN' || last.error === 'no records') return last
    if (attempt < retries) await wait(200 * (attempt + 1))
  }
  return last
}

export function createResolver({
  env = defaultEnv,
  query = queryAll,
  signal,
} = {}) {
  return (hostname) => resolveSubdomainRecords(hostname, { env, query, signal })
}
