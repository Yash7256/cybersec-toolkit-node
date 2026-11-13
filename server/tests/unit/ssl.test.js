import { describe, it, expect, afterEach } from 'vitest'
import tls from 'node:tls'
import net from 'node:net'
import selfsigned from 'selfsigned'
import {
  RESULT_KEYS,
  createSslDefinition,
} from '../../src/tools/ssl/index.js'
import { certInfo } from '../../src/tools/ssl/certInfo.js'

const servers = []

async function listen(server) {
  servers.push(server)
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port))
  })
}

async function makeCert({ commonName = 'localhost', notBeforeDate, notAfterDate } = {}) {
  return selfsigned.generate(
    [
      { name: 'commonName', value: commonName },
      { name: 'organizationName', value: 'Test Org' },
    ],
    {
      notBeforeDate,
      notAfterDate,
      extensions: [
        {
          name: 'subjectAltName',
          altNames: [
            { type: 2, value: commonName },
            { type: 2, value: `www.${commonName}` },
          ],
        },
      ],
    }
  )
}

async function tlsServer(pems) {
  const server = tls.createServer({ key: pems.private, cert: pems.cert }, (socket) =>
    socket.end()
  )
  const port = await listen(server)
  return port
}

function ctx(overrides = {}) {
  return {
    target: { addresses: [{ address: '127.0.0.1' }] },
    env: { SSL_AUDIT_TIMEOUT_MS: 8000 },
    ...overrides,
  }
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) => new Promise((resolve) => server.close(resolve))
    )
  )
})

describe('ssl tool', () => {
  it('reports certificate details and TLS versions', async () => {
    const pems = await makeCert()
    const port = await tlsServer(pems)
    const definition = createSslDefinition()
    const input = definition.normalize({ host: 'localhost', port })
    const result = await definition.execute(input, ctx())

    expect(Object.keys(result).sort()).toEqual([...RESULT_KEYS].sort())
    expect(result.error).toBeNull()
    expect(result.valid).toBe(true)
    expect(result.is_expired).toBe(false)
    expect(result.is_self_signed).toBe(true)
    expect(result.chain_trusted).toBe(false)
    expect(result.authorization_error).toBe('Self-signed certificate')
    expect(result.supports_tls12).toBe(true)
    expect(result.supports_tls13).toBe(true)
    expect(result.tls_version).toMatch(/^TLSv1\.[23]$/)
    expect(result.cipher_suite).toBeTruthy()
    expect(result.hostname_matches).toBe(true)
    expect(result.days_remaining).toBeGreaterThan(0)
    expect(result.certificate).toMatchObject({
      subject: { commonName: 'localhost', organizationName: 'Test Org' },
      san: ['localhost', 'www.localhost'],
    })
    expect(result.certificate.valid_to).toMatch(/Z$/)
  })

  it('flags an expired certificate', async () => {
    const notBeforeDate = new Date(Date.now() - 10 * 86_400_000)
    const notAfterDate = new Date(Date.now() - 86_400_000)
    const pems = await makeCert({ notBeforeDate, notAfterDate })
    const port = await tlsServer(pems)
    const definition = createSslDefinition()
    const result = await definition.execute(
      definition.normalize({ host: 'localhost', port }),
      ctx()
    )

    expect(result.error).toBeNull()
    expect(result.valid).toBe(false)
    expect(result.is_expired).toBe(true)
    expect(result.days_remaining).toBeLessThan(0)
  })

  it('detects a hostname mismatch', async () => {
    const pems = await makeCert()
    const port = await tlsServer(pems)
    const definition = createSslDefinition()
    const result = await definition.execute(
      definition.normalize({ host: 'wrong.test', port }),
      ctx()
    )

    expect(result.error).toBeNull()
    expect(result.hostname_matches).toBe(false)
  })

  it('reports a friendly error for a non-TLS port', async () => {
    const server = net.createServer((socket) => socket.destroy())
    const port = await listen(server)
    const definition = createSslDefinition()
    const result = await definition.execute(
      definition.normalize({ host: 'localhost', port }),
      ctx()
    )

    expect(result.valid).toBe(false)
    expect(['No TLS service on this port', 'TLS handshake failed']).toContain(result.error)
  })

  it('parses certificate fields directly', async () => {
    const pems = await makeCert()
    const info = certInfo(pems.cert, { host: 'localhost' })
    expect(info.key_type).toBe('rsa')
    expect(info.key_bits).toBe(2048)
    expect(info.fingerprint_sha256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/)
    expect(info.issuer.commonName).toBe('localhost')
    expect(info.is_self_signed).toBe(true)
    expect(info.hostname_matches).toBe(true)
  })
})
