import { z } from 'zod'
import { probe as defaultProbe } from './probe.js'
import { certInfo } from './certInfo.js'
import { ToolError } from '../_shared/errors.js'
import { env as defaultEnv } from '../../config/env.js'

export const RESULT_KEYS = [
  'host',
  'port',
  'tls_version',
  'cipher_suite',
  'certificate',
  'valid',
  'is_expired',
  'is_self_signed',
  'days_remaining',
  'supports_tls12',
  'supports_tls13',
  'chain_trusted',
  'authorization_error',
  'hostname_matches',
  'fingerprint_sha256',
  'key_type',
  'key_bits',
  'error',
]

export const schema = z.object({
  host: z.string().trim().min(1).max(260),
  port: z.coerce.number().int().min(1).max(65535).default(443),
})

function emptyResult(input) {
  return {
    host: input.host,
    port: input.port,
    tls_version: null,
    cipher_suite: null,
    certificate: null,
    valid: false,
    is_expired: null,
    is_self_signed: null,
    days_remaining: null,
    supports_tls12: null,
    supports_tls13: null,
    chain_trusted: null,
    authorization_error: null,
    hostname_matches: null,
    fingerprint_sha256: null,
    key_type: null,
    key_bits: null,
    error: null,
  }
}

function friendlyAuthorizationError(code) {
  if (!code) return null
  const text = String(code)
  if (text.includes('SELF_SIGNED')) return 'Self-signed certificate'
  if (text.includes('HOSTNAME')) return 'Hostname mismatch'
  if (text.includes('EXPIRED')) return 'Certificate expired'
  return 'Certificate verification failed'
}

export function createSslDefinition({ probe = defaultProbe, now = Date.now } = {}) {
  return {
    name: 'ssl',
    toolEnum: 'SSL',
    schema,
    touchesTarget: true,
    dedupeTtlSec: 300,
    normalize(input) {
      const host = input.host.trim()
      return { ...input, host: /^https?:\/\//i.test(host) ? new URL(host).hostname : host }
    },
    async execute(input, ctx) {
      const env = ctx.env ?? defaultEnv
      const address = ctx.target.addresses[0]
      const base = {
        address: address.address,
        port: input.port,
        servername: input.host,
        timeoutMs: 5000,
        signal: ctx.signal,
      }

      let timer
      const deadline = new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new ToolError('target', 'Connection timed out')),
          env.SSL_AUDIT_TIMEOUT_MS
        )
      })

      let results
      try {
        results = await Promise.race([
          Promise.allSettled([
            probe(base),
            probe({ ...base, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }),
            probe({ ...base, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }),
          ]),
          deadline,
        ])
      } finally {
        clearTimeout(timer)
      }

      const [secure, tls12, tls13] = results
      if (secure.status === 'rejected') {
        const err = secure.reason
        return {
          ...emptyResult(input),
          error: err instanceof ToolError ? err.message : 'Request failed',
        }
      }

      const info = certInfo(secure.value.cert.raw, { host: input.host, now: now() })
      const certificate = {
        valid_from: info.valid_from,
        valid_to: info.valid_to,
        days_remaining: info.days_remaining,
        issuer: info.issuer,
        subject: info.subject,
        san: info.san,
        is_expired: info.is_expired,
      }

      return {
        host: input.host,
        port: input.port,
        tls_version: secure.value.protocol ?? null,
        cipher_suite: secure.value.cipher?.name ?? null,
        certificate,
        valid: !info.is_expired,
        is_expired: info.is_expired,
        is_self_signed: info.is_self_signed,
        days_remaining: info.days_remaining,
        supports_tls12: tls12.status === 'fulfilled',
        supports_tls13: tls13.status === 'fulfilled',
        chain_trusted: secure.value.authorized,
        authorization_error: friendlyAuthorizationError(secure.value.authorizationError),
        hostname_matches: info.hostname_matches,
        fingerprint_sha256: info.fingerprint_sha256,
        key_type: info.key_type,
        key_bits: info.key_bits,
        error: null,
      }
    },
    emptyResult,
    summarize: (data) => ({ valid: data.valid, error: data.error }),
  }
}

export const definition = createSslDefinition()
