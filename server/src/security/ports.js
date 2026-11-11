import { z } from 'zod'
import AppError from '../utils/AppError.js'
import {
  MAX_PORT_LIST_ENTRIES,
  MAX_PORT_RANGE_SPAN,
  MAX_PORTS_PER_SCAN,
} from '../config/limits.js'

const SINGLE = /^(0|[1-9]\d{0,4})$/
const RANGE = /^(0|[1-9]\d{0,4})-(0|[1-9]\d{0,4})$/

function invalid() {
  return new AppError(422, 'TARGET_INVALID', 'Port specification is invalid.')
}

function toTokens(input) {
  if (typeof input === 'string') {
    return input.split(',')
  }
  if (Array.isArray(input)) {
    return input
  }
  throw invalid()
}

function parsePortNumber(value) {
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw invalid()
  return port
}

function parseToken(token) {
  if (typeof token === 'number') {
    return { start: parsePortNumber(token), end: parsePortNumber(token), span: 1 }
  }
  if (typeof token !== 'string') throw invalid()

  const value = token.trim()
  if (SINGLE.test(value)) {
    const port = parsePortNumber(value)
    return { start: port, end: port, span: 1 }
  }

  const match = RANGE.exec(value)
  if (!match) throw invalid()

  const start = parsePortNumber(match[1])
  const end = parsePortNumber(match[2])
  if (end < start) throw invalid()

  const span = end - start + 1
  if (span > MAX_PORT_RANGE_SPAN) throw invalid()
  return { start, end, span }
}

export function parsePorts(input) {
  const rawTokens = toTokens(input)
  if (rawTokens.length === 0) throw invalid()
  if (rawTokens.length > MAX_PORT_LIST_ENTRIES) throw invalid()

  // Validate every token and bound the total BEFORE allocating the result.
  const ranges = []
  let upperBound = 0
  for (const raw of rawTokens) {
    if (typeof raw === 'string' && raw.trim() === '') throw invalid()
    const range = parseToken(raw)
    upperBound += range.span
    if (upperBound > MAX_PORTS_PER_SCAN) throw invalid()
    ranges.push(range)
  }

  const ports = new Set()
  for (const range of ranges) {
    for (let port = range.start; port <= range.end; port += 1) ports.add(port)
  }

  if (ports.size > MAX_PORTS_PER_SCAN) throw invalid()
  return [...ports].sort((a, b) => a - b)
}

export const portsSchema = z
  .union([z.string(), z.array(z.union([z.number(), z.string()]))])
  .transform((value, ctx) => {
    try {
      return parsePorts(value)
    } catch {
      ctx.addIssue({ code: 'custom', message: 'Port specification is invalid.' })
      return z.NEVER
    }
  })
