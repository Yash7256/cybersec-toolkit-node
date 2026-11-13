import { describe, it, expect } from 'vitest'

describe.skipIf(!process.env.LOAD_TESTS)('Phase 6 load test', () => {
  it('is enabled explicitly in a provisioned load environment', async () => {
    expect(process.env.LOAD_TESTS).toBe('1')
  })
})
