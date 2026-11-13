import { X509Certificate } from 'node:crypto'

const DN_KEYS = {
  CN: 'commonName',
  O: 'organizationName',
  C: 'countryName',
  ST: 'stateOrProvinceName',
  L: 'localityName',
  OU: 'organizationalUnitName',
}

function parseDn(dn) {
  const out = {}
  for (const line of String(dn ?? '').split('\n')) {
    const separator = line.indexOf('=')
    if (separator <= 0) continue
    const key = line.slice(0, separator).trim()
    const value = line.slice(separator + 1).trim()
    out[DN_KEYS[key] ?? key] = value
  }
  return out
}

export function certInfo(raw, { host, now = Date.now() } = {}) {
  const x509 = new X509Certificate(raw)
  const validFrom = new Date(x509.validFrom)
  const validTo = new Date(x509.validTo)
  const daysRemaining = Math.floor((validTo.getTime() - now) / 86_400_000)
  const san = String(x509.subjectAltName ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith('DNS:'))
    .map((entry) => entry.slice(4))

  return {
    valid_from: validFrom.toISOString(),
    valid_to: validTo.toISOString(),
    days_remaining: daysRemaining,
    issuer: parseDn(x509.issuer),
    subject: parseDn(x509.subject),
    san,
    is_expired: validTo.getTime() < now,
    is_self_signed: x509.subject === x509.issuer && x509.verify(x509.publicKey),
    hostname_matches: host ? Boolean(x509.checkHost(host)) : false,
    fingerprint_sha256: x509.fingerprint256,
    key_type: x509.publicKey.asymmetricKeyType ?? null,
    key_bits: x509.publicKey.asymmetricKeyDetails?.modulusLength ?? null,
  }
}
