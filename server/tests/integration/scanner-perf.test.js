import { describe, it, expect } from 'vitest'
import net from 'node:net'
import { scanPorts } from '../../src/scanner/engine.js'

const enabled = process.env.PERF_TESTS === '1'

function closedPort() {
  return new Promise((resolve) => {
    const server = net.createServer()
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port
      server.close(() => resolve(port))
    })
  })
}

describe.skipIf(!enabled)('scanner performance envelope', () => {
  it('scans 1000 closed loopback ports in under 5 seconds', async () => {
    const base = await closedPort()
    const ports = Array.from({ length: 1000 }, (_, index) => ((base + index) % 60000) + 1)
    const started = Date.now()
    const result = await scanPorts({
      address: '127.0.0.1',
      family: 4,
      hostname: 'localhost',
      ports,
      timeoutMs: 250,
      concurrency: 200,
      ratePerSec: 10000,
    })
    expect(Date.now() - started).toBeLessThan(5000)
    expect(result.total_scanned).toBe(1000)
  })

  it('keeps a 5000-port timeout sweep near the theoretical bound', async () => {
    const started = Date.now()
    const result = await scanPorts({
      address: '192.0.2.1',
      family: 4,
      hostname: 'perf.test',
      ports: Array.from({ length: 5000 }, (_, index) => 20000 + index),
      timeoutMs: 500,
      concurrency: 200,
      ratePerSec: 20000,
    })
    const elapsed = (Date.now() - started) / 1000
    const theoretical = 5000 / 200 * 0.5
    expect(elapsed).toBeLessThan(theoretical * 1.15 + 1)
    expect(result.total_scanned).toBe(5000)
  }, 30000)
})
