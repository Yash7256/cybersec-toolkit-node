import net from 'node:net'
import ipaddr from 'ipaddr.js'
import { z } from 'zod'
import { queryAll as defaultQueryAll, TYPE_NAMES } from '../../net/dohClient.js'
import { ToolError } from '../_shared/errors.js'

export const RESULT_KEYS = [
  'target',
  'record_type',
  'records',
  'query_time_ms',
  'error',
  'dnssec_validated',
  'resolver',
]

const types = ['ALL', 'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'PTR']
const ALL_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA']

export const schema = z.object({
  target: z.string().trim().min(1).max(260),
  record_type: z.enum(types).default('ALL'),
})

function emptyResult(input) {
  return {
    target: input.target,
    record_type: input.record_type,
    records: [],
    query_time_ms: 0,
    error: null,
    dnssec_validated: false,
    resolver: 'Cloudflare DoH',
  }
}

export function reverseName(ip) {
  const family = net.isIP(ip)
  if (family === 4) return `${ip.split('.').reverse().join('.')}.in-addr.arpa`
  if (family === 6) {
    const bytes = ipaddr.parse(ip).toByteArray()
    const hex = bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('')
    return `${hex.split('').reverse().join('.')}.ip6.arpa`
  }
  return null
}

function unquoteTxt(value) {
  const chunks = value.match(/"((?:\\.|[^"\\])*)"/g)
  if (!chunks) return value
  return chunks.map((chunk) => chunk.slice(1, -1).replace(/\\"/g, '"')).join('')
}

function mapAnswer(answer, fallbackType) {
  const type = TYPE_NAMES[answer.type] ?? fallbackType
  const data = String(answer.data ?? '')
  const record = { type, ttl: answer.TTL ?? null }

  if (type === 'MX') {
    const [priority, ...exchange] = data.trim().split(/\s+/)
    record.priority = Number(priority)
    record.value = exchange.join(' ')
  } else if (type === 'SOA') {
    const parts = data.trim().split(/\s+/)
    record.value = parts[0]
    record.mname = parts[0]
    record.rname = parts[1]
    record.serial = Number(parts[2])
  } else if (type === 'TXT') {
    record.value = unquoteTxt(data)
  } else {
    record.value = data
  }

  return record
}

export function createDnsDefinition({ doh = { queryAll: defaultQueryAll } } = {}) {
  return {
    name: 'dns',
    toolEnum: 'DNS',
    schema,
    touchesTarget: false,
    dedupeTtlSec: 60,
    normalize(input) {
      const target = input.target.trim()
      const isIp = net.isIP(target) !== 0
      return { ...input, target, record_type: isIp ? 'PTR' : input.record_type }
    },
    async execute(input) {
      const started = Date.now()
      const typesToQuery = input.record_type === 'ALL' ? ALL_TYPES : [input.record_type]
      let name = input.target
      if (input.record_type === 'PTR') {
        const reverse = reverseName(input.target)
        if (!reverse) throw new ToolError('target', 'Target returned an invalid response')
        name = reverse
      }

      const results = await doh.queryAll(name, typesToQuery)

      const records = []
      let dnssecValidated = false
      let resolver = null
      let error = null

      for (const result of results) {
        if (result.error) {
          if (result.error.kind === 'upstream') {
            error ??= 'Lookup service unavailable'
          } else if (result.error.message === 'Query timed out') {
            error ??= 'Query timed out'
          } else {
            error ??= 'Lookup service unavailable'
          }
          continue
        }
        const body = result.data ?? {}
        if (body.Status === 3) {
          error = 'Domain not found'
          break
        }
        if (body.Status !== 0) {
          error ??= 'Lookup service unavailable'
          continue
        }
        resolver ??= result.resolver
        if (body.AD === true) dnssecValidated = true
        for (const answer of body.Answer ?? []) {
          records.push(mapAnswer(answer, result.type))
        }
      }

      if (records.length > 0) error = null
      else if (!error) error = 'No records of this type'

      return {
        target: input.target,
        record_type: input.record_type,
        records,
        query_time_ms: Date.now() - started,
        error,
        dnssec_validated: dnssecValidated,
        resolver: resolver ?? 'Cloudflare DoH',
      }
    },
    emptyResult,
    summarize: (data) => ({
      recordCount: data.records?.length ?? 0,
      types: [...new Set((data.records ?? []).map((record) => record.type))],
      error: data.error,
    }),
  }
}

export const definition = createDnsDefinition()
