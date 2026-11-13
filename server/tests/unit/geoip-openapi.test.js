import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import tools from '../../src/tools/index.js'

const spec = readFileSync(fileURLToPath(new URL('../../../docs/openapi/geoip.yaml', import.meta.url)), 'utf8')

function pathBlock(path) {
  const start = spec.indexOf(`\n  ${path}:\n`)
  if (start === -1) return ''
  const rest = spec.slice(start + path.length + 5)
  const next = rest.search(/\n  \/[^\n]+:\n/)
  return next === -1 ? rest : rest.slice(0, next)
}

const expected = {
  '/tools/geoip': ['get'],
  '/tools/geoip/me': ['get'],
  '/tools/geoip/history': ['get', 'delete'],
  '/tools/geoip/cidr': ['get', 'post'],
  '/tools/geoip_bulk': ['post'],
  '/tools/asn': ['get', 'post'],
  '/runs/{id}/share': ['post'],
  '/runs/{id}/shares': ['get'],
  '/runs/{id}/share/{shareId}': ['delete'],
  '/runs/compare': ['get'],
  '/runs/{id}/report': ['get'],
  '/share/{token}': ['get'],
}

describe('GeoIP OpenAPI contract', () => {
  it('documents every new workflow route and method', () => {
    for (const [path, methods] of Object.entries(expected)) {
      const block = pathBlock(path)
      expect(block, `${path} missing from OpenAPI spec`).not.toBe('')
      for (const method of methods) expect(block, `${method.toUpperCase()} ${path} missing`).toMatch(new RegExp(`(?:^|\\n)    ${method}:`))
    }
  })

  it('matches registered tool names and request fields', () => {
    for (const [name, path] of [['geoip', '/tools/geoip'], ['geoip_bulk', '/tools/geoip_bulk'], ['geoip_cidr', '/tools/geoip/cidr'], ['asn', '/tools/asn']]) {
      expect(tools[name], `${name} missing from tool registry`).toBeTruthy()
      expect(spec).toContain(`${path}:`)
    }
    const bulk = tools.geoip_bulk.schema.shape
    const cidr = tools.geoip_cidr.schema.shape
    const asn = tools.asn.schema.shape
    expect(Object.keys(bulk)).toEqual(['targets'])
    expect(Object.keys(cidr)).toEqual(['target'])
    expect(Object.keys(asn)).toEqual(['asn'])
    expect(pathBlock('/tools/geoip_bulk')).toContain('targets:')
    expect(pathBlock('/tools/geoip/cidr')).toContain('target:')
    expect(pathBlock('/tools/asn')).toContain('asn:')
  })
})
