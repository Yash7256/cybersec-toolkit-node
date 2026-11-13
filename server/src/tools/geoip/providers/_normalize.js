const CONTINENT_NAMES = {
  AF: 'Africa',
  AN: 'Antarctica',
  AS: 'Asia',
  EU: 'Europe',
  NA: 'North America',
  OC: 'Oceania',
  SA: 'South America',
}

const regionNames = new Intl.DisplayNames(['en'], { type: 'region' })

function normalizeCode(code) {
  const value = String(code ?? '').trim().toUpperCase()
  return /^[A-Z]{2}$/.test(value) ? value : null
}

export function countryName(code) {
  const normalized = normalizeCode(code)
  if (!normalized) return null
  try {
    const name = regionNames.of(normalized)
    return name && name !== 'Unknown Region' ? name : null
  } catch {
    return null
  }
}

export function flagEmoji(code) {
  const normalized = normalizeCode(code)
  if (!normalized) return null
  return String.fromCodePoint(
    ...[...normalized].map((letter) => 0x1f1e6 + letter.charCodeAt(0) - 65)
  )
}

export function continentName(code) {
  const normalized = normalizeCode(code)
  return normalized ? CONTINENT_NAMES[normalized] ?? null : null
}

export function boolOrNull(value) {
  return value === true ? true : value === false ? false : null
}
