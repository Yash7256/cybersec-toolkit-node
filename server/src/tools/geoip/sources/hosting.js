import { readFileSync } from 'node:fs'

const DATA = JSON.parse(readFileSync(new URL('../data/hosting-asns.json', import.meta.url), 'utf8'))
const HOSTING = new Set(Object.keys(DATA.asns ?? {}).map((asn) => asn.toUpperCase()))

export function hostingStatus(asn) {
  if (!asn) return null
  const normalized = String(asn).trim().toUpperCase()
  if (!/^AS\d+$/.test(normalized)) return null
  return HOSTING.has(normalized)
}

export function hostingProvider(asn) {
  if (!asn) return null
  return DATA.asns?.[String(asn).trim().toUpperCase()] ?? null
}

export const hostingListUpdated = DATA.updated ?? null
