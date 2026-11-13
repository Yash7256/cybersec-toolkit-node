import { MITRE_PORT_MAPPINGS, POTENTIAL_THREATS } from '../data/portRegistry.js'

export { MITRE_PORT_MAPPINGS, POTENTIAL_THREATS }

export const MITRE_SERVICE_MAPPINGS = {
  ssh: MITRE_PORT_MAPPINGS[22],
  telnet: MITRE_PORT_MAPPINGS[23],
  smb: MITRE_PORT_MAPPINGS[445],
  rdp: MITRE_PORT_MAPPINGS[3389],
  ftp: MITRE_PORT_MAPPINGS[21],
  http: MITRE_PORT_MAPPINGS[80],
  'http-proxy': MITRE_PORT_MAPPINGS[8080],
  https: MITRE_PORT_MAPPINGS[443],
  'https-alt': MITRE_PORT_MAPPINGS[8443],
  mysql: MITRE_PORT_MAPPINGS[3306],
  postgresql: MITRE_PORT_MAPPINGS[5432],
  redis: MITRE_PORT_MAPPINGS[6379],
  mongodb: MITRE_PORT_MAPPINGS[27017],
  vnc: MITRE_PORT_MAPPINGS[5900],
}

export function mitreUrl(techniqueId) {
  return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`
}

export function addMitreAttackMapping(openPorts) {
  for (const port of openPorts) {
    const serviceKey = String(port.service || '').toLowerCase()
    const mapped = [
      ...(MITRE_PORT_MAPPINGS[port.port_number] ?? []),
      ...(MITRE_SERVICE_MAPPINGS[serviceKey] ?? []),
    ]

    const seen = new Set()
    const techniques = []
    for (const [techniqueId, name, tactic] of mapped) {
      if (seen.has(techniqueId)) continue
      seen.add(techniqueId)
      techniques.push({
        technique_id: techniqueId,
        technique_name: name,
        tactic,
        url: mitreUrl(techniqueId),
        attack_vector: `${port.service} exposure on TCP/${port.port_number}`,
        threat_behavior: name,
      })
    }

    port.mitre_attack = techniques
    port.potential_threat = techniques.length
      ? POTENTIAL_THREATS[port.port_number] ??
        `Reconnaissance or exploitation attempts may be possible against ${port.service} on port ${port.port_number}.`
      : null
  }
  return openPorts
}
