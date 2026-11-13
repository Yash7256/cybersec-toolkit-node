import { HTTP_PORTS, WELCOME_PORTS } from './constants.js'
import { COMMON_PORTS } from './data/portRegistry.js'
import { parseVersionString } from './cve/cpe.js'

export function fingerprintMethod(port) {
  if (HTTP_PORTS.has(port.port_number)) return 'HTTP banner and technology detection'
  if (WELCOME_PORTS.has(port.port_number)) return 'Protocol banner'
  return 'TCP port mapping'
}

export function calculateFingerprintConfidence(port) {
  const evidence = []
  let score = 35

  if (port.port_number in COMMON_PORTS) {
    score += 12
    evidence.push('known port mapping')
  }
  if (port.raw_banner) {
    score += 20
    evidence.push('raw banner captured')
  }
  if (port.server_response) {
    score += 12
    evidence.push('server response captured')
  }
  if (port.welcome_message) {
    score += 10
    evidence.push('welcome banner captured')
  }
  if (port.version) {
    score += 24
    evidence.push('version string parsed')
    const parsed = parseVersionString(port.version)
    if (parsed && /\d+\.\d+/.test(parsed[1])) {
      score += 8
      evidence.push('specific version number')
    }
  }
  if (port.technologies?.length) {
    score += Math.min(12, 4 * port.technologies.length)
    evidence.push('technology signatures matched')
  }

  if (!(port.raw_banner || port.server_response || port.welcome_message || port.version)) {
    score -= 18
    evidence.push('no banner evidence')
  }
  if (port.service === 'Unknown') {
    score -= 10
    evidence.push('unknown service')
  }

  const confidence = Math.max(20, Math.min(99, score))
  const detected = port.version || (
    port.service && port.service !== 'Unknown' ? `${port.service} service` : `TCP/${port.port_number}`
  )

  return {
    detected,
    confidence,
    method: fingerprintMethod(port),
    evidence: evidence.slice(0, 5),
  }
}

export function addServiceFingerprints(openPorts) {
  for (const port of openPorts) {
    port.fingerprint = calculateFingerprintConfidence(port)
  }
  return openPorts
}
