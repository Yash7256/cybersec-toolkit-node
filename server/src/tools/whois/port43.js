import net from 'node:net'
import { resolveTarget } from '../../security/resolve.js'
import { ToolError, mapNetworkError } from '../_shared/errors.js'

const MAX_BYTES = 10 * 1024
const TIMEOUT_MS = 8000

const NOT_FOUND = /no match|not found|no entries found|no data found|no object found|nothing found/i

export function parseWhois(text) {
  const result = {
    registrar: null,
    creation_date: null,
    expiration_date: null,
    updated_date: null,
    name_servers: [],
    status: [],
    emails: [],
    raw_text: String(text ?? '').slice(0, MAX_BYTES),
  }

  for (const line of String(text ?? '').split(/\r?\n/)) {
    const separator = line.indexOf(':')
    if (separator <= 0) continue
    const key = line.slice(0, separator).trim().toLowerCase()
    const value = line.slice(separator + 1).trim()
    if (!value || value.startsWith('%') || value.startsWith('#')) continue

    if (key === 'registrar' || key === 'sponsoring registrar') {
      result.registrar ??= value
    } else if (key === 'creation date' || key === 'created' || key === 'registered on' || key === 'registration date') {
      result.creation_date ??= parseDate(value)
    } else if (key === 'registry expiry date' || key === 'expiry date' || key === 'expiration date' || key === 'expires on') {
      result.expiration_date ??= parseDate(value)
    } else if (key === 'updated date' || key === 'last updated' || key === 'last modified') {
      result.updated_date ??= parseDate(value)
    } else if (key === 'name server' || key === 'nameserver' || key === 'nserver') {
      const server = value.split(/\s+/)[0].toLowerCase()
      if (server && !result.name_servers.includes(server)) result.name_servers.push(server)
    } else if (key === 'domain status' || key === 'status') {
      const status = value.split(/\s+/)[0]
      if (status && !result.status.includes(status)) result.status.push(status)
    } else if (key.includes('email')) {
      const email = value.match(/[^\s@]+@[^\s@]+\.[^\s@]+/)?.[0]
      if (email && !result.emails.includes(email)) result.emails.push(email)
    }
  }

  return result
}

export function isNotFound(text) {
  return NOT_FOUND.test(String(text ?? ''))
}

function queryServer(server, query) {
  return new Promise((resolve, reject) => {
    let settled = false
    let bytes = 0
    const chunks = []

    const finish = (err) => {
      if (settled) return
      settled = true
      socket.destroy()
      if (err) reject(err)
      else resolve(Buffer.concat(chunks).toString('utf8'))
    }

    const socket = net.connect({ host: server, port: 43, timeout: TIMEOUT_MS })
    socket.once('connect', () => socket.write(`${query}\r\n`))
    socket.on('data', (chunk) => {
      bytes += chunk.length
      if (bytes > MAX_BYTES) {
        chunks.push(chunk.subarray(0, Math.max(0, MAX_BYTES - (bytes - chunk.length))))
        finish()
        return
      }
      chunks.push(chunk)
    })
    socket.once('end', () => finish())
    socket.once('timeout', () => finish(new ToolError('upstream', 'Lookup service unavailable')))
    socket.once('error', (err) => finish(mapNetworkError(err)))
  })
}

async function queryPublicServer(server, query) {
  const { addresses } = await resolveTarget(server, { kind: 'hostname' })
  return queryServer(addresses[0].address, query)
}

export async function port43Lookup(domain, { query = queryPublicServer } = {}) {
  const iana = await query('whois.iana.org', domain)
  const refer = iana.match(/^(?:refer|whois):\s*(\S+)/im)?.[1]
  const body = refer ? await query(refer, domain) : iana
  if (isNotFound(body)) return { available: true, ...parseWhois(body) }
  return { available: false, ...parseWhois(body) }
}

const MONTHS = {
  jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06',
  jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12',
}

function parseDate(value) {
  const text = value.replace(/\s+\(.*\)$/, '').trim()

  const dayMonthYear = text.match(/^(\d{1,2})-([a-z]{3})-(\d{4})$/i)
  if (dayMonthYear) {
    const month = MONTHS[dayMonthYear[2].toLowerCase()]
    if (month) {
      return `${dayMonthYear[3]}-${month}-${dayMonthYear[1].padStart(2, '0')}`
    }
  }

  const dateOnly = text.match(/^(\d{4})[-/.](\d{2})[-/.](\d{2})$/)
  if (dateOnly) return `${dateOnly[1]}-${dateOnly[2]}-${dateOnly[3]}`

  const parsed = new Date(text)
  if (!Number.isNaN(parsed.getTime())) return parsed.toISOString().slice(0, 10)
  return text
}
