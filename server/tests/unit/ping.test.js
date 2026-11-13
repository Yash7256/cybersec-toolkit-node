import { describe, it, expect, vi, afterEach } from 'vitest'
import net from 'node:net'
import {
  RESULT_KEYS,
  createPingDefinition,
  schema,
} from '../../src/tools/ping/index.js'
import { tcpPing } from '../../src/tools/ping/tcp.js'
import { ToolError } from '../../src/tools/_shared/errors.js'

const servers = []

async function listen(server) {
  servers.push(server)
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve)))
  )
})

const ctx = {
  target: { addresses: [{ address: '127.0.0.1', family: 4 }] },
  userId: 'user-1',
}

function makeDefinition({ tcp, icmp, env = {}, history = null, geo = async () => ({}) } = {}) {
  return createPingDefinition({
    tcpPing: tcp,
    icmpPing: icmp,
    platform: env.platform ?? 'linux',
    hasPing: env.hasPing ?? true,
    history,
    geo,
  })
}

describe('ping tool', () => {
  it('returns TCP latency statistics', async () => {
    const tcp = vi.fn().mockResolvedValue({
      method: 'tcp',
      port: 443,
      values: [10, 20, 30, 40],
      sent: 4,
      received: 4,
      loss_pct: 0,
    })
    const definition = makeDefinition({ tcp, env: { PING_METHOD: 'tcp' } })
    const result = await definition.execute({ target: 'example.com', count: 4 }, {
      ...ctx,
      env: { PING_METHOD: 'tcp', PING_HISTORY_TTL_SEC: 3600 },
    })

    expect(Object.keys(result)).toEqual(expect.arrayContaining(RESULT_KEYS))
    expect(result.method).toBe('tcp')
    expect(result.avg_ms).toBe(25)
    expect(result.min_ms).toBe(10)
    expect(result.max_ms).toBe(40)
    expect(result.quality).toBe('good')
    expect(result.loss_pct).toBe(0)
  })

  it('reports 100% loss for a closed port', async () => {
    const server = net.createServer()
    const port = await listen(server)
    await new Promise((resolve) => server.close(resolve))
    servers.splice(servers.indexOf(server), 1)

    const result = await tcpPing({ address: '127.0.0.1', count: 2, ports: [port], timeoutMs: 200 })
    expect(result.received).toBe(0)
    expect(result.loss_pct).toBe(100)
  })

  it('uses ICMP when forced and falls back to TCP in auto mode', async () => {
    const icmp = vi.fn().mockRejectedValue(new ToolError('target', 'Host not reachable'))
    const tcp = vi.fn().mockResolvedValue({
      method: 'tcp', port: 443, values: [5], sent: 1, received: 1, loss_pct: 0,
    })

    const forced = makeDefinition({ icmp, tcp, env: { PING_METHOD: 'icmp' } })
    await expect(
      forced.execute({ target: 'example.com', count: 1 }, { ...ctx, env: { PING_METHOD: 'icmp' } })
    ).rejects.toMatchObject({ kind: 'target' })

    const auto = makeDefinition({ icmp, tcp, env: { PING_METHOD: 'auto' } })
    const result = await auto.execute(
      { target: 'example.com', count: 1 },
      { ...ctx, env: { PING_METHOD: 'auto' } }
    )
    expect(result.method).toBe('tcp')
    expect(icmp).toHaveBeenCalled()
    expect(tcp).toHaveBeenCalled()
  })

  it('uses TCP on non-Linux platforms', async () => {
    const icmp = vi.fn()
    const tcp = vi.fn().mockResolvedValue({
      method: 'tcp', port: 443, values: [5], sent: 1, received: 1, loss_pct: 0,
    })
    const definition = makeDefinition({
      icmp,
      tcp,
      env: { PING_METHOD: 'auto', platform: 'win32', hasPing: true },
    })
    const result = await definition.execute(
      { target: 'example.com', count: 1 },
      { ...ctx, env: { PING_METHOD: 'auto' } }
    )
    expect(result.method).toBe('tcp')
    expect(icmp).not.toHaveBeenCalled()
  })

  it('reports a history delta across runs', async () => {
    let stored = 20
    const history = {
      get: async () => stored,
      set: async (_user, _target, value) => {
        stored = value
      },
    }
    const tcp = vi.fn().mockResolvedValue({
      method: 'tcp', port: 443, values: [30], sent: 1, received: 1, loss_pct: 0,
    })
    const definition = makeDefinition({ tcp, history })
    const first = await definition.execute(
      { target: 'example.com', count: 1 },
      { ...ctx, env: { PING_METHOD: 'tcp' } }
    )
    expect(first.history_delta_ms).toBe(10)

    const second = await definition.execute(
      { target: 'example.com', count: 1 },
      { ...ctx, env: { PING_METHOD: 'tcp' } }
    )
    expect(second.history_delta_ms).toBe(0)
  })

  it('does not fail when geo enrichment fails', async () => {
    const tcp = vi.fn().mockResolvedValue({
      method: 'tcp', port: 443, values: [5], sent: 1, received: 1, loss_pct: 0,
    })
    const definition = makeDefinition({
      tcp,
      geo: async () => {
        throw new Error('geo down')
      },
    })
    const result = await definition.execute(
      { target: 'example.com', count: 1 },
      { ...ctx, env: { PING_METHOD: 'tcp' } }
    )
    expect(result.geo).toEqual({})
    expect(result.error).toBeNull()
  })

  it('caps count at 20', () => {
    expect(() => schema.parse({ target: 'example.com', count: 21 })).toThrow()
    expect(schema.parse({ target: 'example.com', count: 20 }).count).toBe(20)
  })
})
