import { describe, expect, it } from 'vitest'
import { classifyInput, expandCidr } from '../../src/tools/geoip/classify.js'
import { buildPlan } from '../../src/tools/geoip/plan.js'

const env = { GEOIP_BULK_MAX_FREE: 10, GEOIP_BULK_MAX_PAID: 100 }

describe('unified GeoIP classifier and planner', () => {
  it('classifies strict ASN and masks non-aligned CIDR input', () => {
    const result = classifyInput('AS15169 15169 8.8.8.5/24')
    expect(result.tokens).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'asn', canonical: 'AS15169' }),
      expect.objectContaining({ kind: 'invalid', reason: 'Did you mean AS<n>?' }),
      expect.objectContaining({ kind: 'cidr', canonical: '8.8.8.0/24' }),
    ]))
  })

  it('expands CIDR with network and broadcast addresses available to policy skipping', () => {
    expect(expandCidr('8.8.8.0/30')).toMatchObject({ cidr: '8.8.8.0/30', addresses: ['8.8.8.0', '8.8.8.1', '8.8.8.2', '8.8.8.3'] })
    expect(buildPlan('8.8.8.0/30', { env })).toMatchObject({ mode: 'batch', units: 2, skipped: [{ input: '8.8.8.0' }, { input: '8.8.8.3' }] })
  })

  it('selects output mode from the resulting unit count', () => {
    expect(buildPlan('8.8.8.8', { env }).mode).toBe('single')
    expect(buildPlan('AS15169', { env }).mode).toBe('asn')
    expect(buildPlan('8.8.8.8 example.com', { env }).mode).toBe('batch')
  })
})
