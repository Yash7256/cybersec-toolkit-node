import { HTTPS_PORTS, WEAK_TLS_CIPHER_MARKERS } from '../constants.js'
import { misconfiguration } from './misconfig.js'

export function detectTlsMisconfiguration(port, sslResult) {
  if (!HTTPS_PORTS.has(port.port_number)) return []

  if (!sslResult || sslResult instanceof Error) {
    return [
      misconfiguration(
        'weak_ssl',
        'Weak SSL/TLS configuration',
        'medium',
        'TLS audit failed for this service.',
        'Review TLS configuration and verify supported protocols, ciphers, and certificate chain.'
      ),
    ]
  }

  const findings = []
  if (sslResult.error) {
    findings.push(
      misconfiguration(
        'weak_ssl',
        'Weak SSL/TLS configuration',
        'medium',
        sslResult.error,
        'Review TLS configuration and certificate deployment for this HTTPS service.'
      )
    )
    return findings
  }

  const cipherName = sslResult.cipher_suite || ''
  const weakCipher = [...WEAK_TLS_CIPHER_MARKERS].some((marker) =>
    cipherName.toUpperCase().includes(marker)
  )
  if (weakCipher || sslResult.tls_version === 'TLSv1' || sslResult.tls_version === 'TLSv1.1' || sslResult.supports_tls12 === false) {
    const evidence = []
    if (cipherName) evidence.push(`Cipher: ${cipherName}`)
    if (sslResult.tls_version) evidence.push(`Negotiated: ${sslResult.tls_version}`)
    if (sslResult.supports_tls12 === false) evidence.push('TLS 1.2 not supported')
    findings.push(
      misconfiguration(
        'weak_ssl',
        'Weak SSL ciphers',
        'high',
        evidence.join('; ') || 'Weak TLS settings were detected.',
        'Disable legacy protocols and weak ciphers; require TLS 1.2 or newer with modern cipher suites.'
      )
    )
  }

  if (sslResult.is_self_signed) {
    findings.push(
      misconfiguration(
        'weak_ssl',
        'Self-signed SSL certificate',
        'medium',
        'The HTTPS service uses a self-signed certificate.',
        'Use a certificate issued by a trusted CA for public-facing services.'
      )
    )
  }
  const certificate = sslResult.certificate ?? sslResult.cert
  if (certificate?.is_expired) {
    findings.push(
      misconfiguration(
        'weak_ssl',
        'Expired SSL certificate',
        'high',
        'The HTTPS certificate is expired.',
        'Renew and deploy a valid certificate for this service.'
      )
    )
  }
  return findings
}
