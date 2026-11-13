import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { safeHostHeader } from '../../src/scanner/bannerProbe.js'

const SRC = new URL('../../src/', import.meta.url).pathname

function filesUnder(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    if (entry === 'generated') continue
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) out.push(...filesUnder(path))
    else if (entry.endsWith('.js')) out.push(path)
  }
  return out
}

const FILES = filesUnder(SRC).map((path) => ({
  path,
  relative: relative(SRC, path).replaceAll('\\', '/'),
  text: readFileSync(path, 'utf8'),
}))

describe('scanner security invariants', () => {
  it('keeps raw net/tls connections inside connect.js', () => {
    const offenders = FILES.filter(
      (file) =>
        file.relative.startsWith('scanner/') &&
        file.relative !== 'scanner/connect.js' &&
        /\b(?:net|tls)\.connect\s*\(/.test(file.text)
    )
    expect(offenders.map((file) => file.relative)).toEqual([])
  })

  it('never uses the unsafe Prisma raw helpers', () => {
    const offenders = FILES.filter((file) =>
      /\$(?:query|execute)RawUnsafe\b/.test(file.text)
    )
    expect(offenders.map((file) => file.relative)).toEqual([])
  })

  it('routes outbound HTTP through safeHttp or an injected client', () => {
    const allowed = new Set(['net/nvdClient.js', 'scanner/intel/threatIntel.js'])
    const offenders = FILES.filter(
      (file) =>
        !allowed.has(file.relative) &&
        (/\bfetch\s*\(/.test(file.text) ||
          /(?:http|https)\.request\s*\(/.test(file.text) ||
          /axios/.test(file.text))
    )
    expect(offenders.map((file) => file.relative)).toEqual([])

    for (const name of allowed) {
      const file = FILES.find((entry) => entry.relative === name)
      expect(file.text).toMatch(/safeHttp/)
      expect(file.text).toMatch(/http\.request/)
    }
  })

  it('sanitizes the Host header built from user input', () => {
    expect(safeHostHeader('example.com', '93.184.216.34')).toBe('example.com')
    expect(safeHostHeader('EXAMPLE.com', '93.184.216.34')).toBe('example.com')
    expect(safeHostHeader('example.com\r\nX-Injected: 1', '93.184.216.34')).toBe('93.184.216.34')
    expect(safeHostHeader('bad host', '::1')).toBe('::1')
    expect(safeHostHeader(undefined, '93.184.216.34')).toBe('93.184.216.34')
  })
})
