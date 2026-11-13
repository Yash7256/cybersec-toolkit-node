import { safeHttp } from '../../../net/safeHttp.js'
import { boolOrNull, countryName, flagEmoji } from './_normalize.js'

function normalizeCountry(code) {
  const value = String(code ?? '').trim()
  if (!value) return null
  const resolved = countryName(value)
  return resolved ?? value
}

function asnFromOrg(org) {
  return String(org ?? '').match(/AS\d+/i)?.[0] ?? null
}

export function createProvider({ client = safeHttp } = {}) {
  return {
    name: 'ipinfo',
    async lookup(ip, { token, signal } = {}) {
      const response = await client.request(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, {
        mode: 'trusted',
        allowHosts: ['ipinfo.io'],
        headers: token ? { authorization: `Bearer ${token}` } : {},
        maxBytes: 128 * 1024,
        signal,
      })
      const data = JSON.parse(response.body.toString('utf8'))
      if (data.bogon) throw new Error('provider failed')
      const [latitude, longitude] = String(data.loc ?? ',').split(',').map(Number)
      const rawCountry = String(data.country ?? '').trim().toUpperCase()
      const countryCode = /^[A-Z]{2}$/.test(rawCountry) ? rawCountry : null
      const continentCode = data.continent?.code ?? null
      const org = data.org ?? null
      return {
        ip: data.ip ?? ip,
        country: normalizeCountry(data.country),
        country_code: countryCode,
        continent: data.continent?.name ?? null,
        continent_code: continentCode,
        region: data.region ?? null,
        city: data.city ?? null,
        postal: data.postal ?? null,
        latitude: Number.isFinite(latitude) ? latitude : null,
        longitude: Number.isFinite(longitude) ? longitude : null,
        timezone: data.timezone ?? null,
        utc_offset: null,
        flag_emoji: flagEmoji(countryCode),
        calling_code: null,
        asn: data.asn?.asn ?? asnFromOrg(org),
        org,
        isp: null,
        asn_domain: data.asn?.domain ?? null,
        is_proxy: data.privacy ? boolOrNull(data.privacy.proxy) : null,
        is_hosting: data.privacy ? boolOrNull(data.privacy.hosting) : null,
        is_vpn: data.privacy ? boolOrNull(data.privacy.vpn) : null,
        is_tor: data.privacy ? boolOrNull(data.privacy.tor) : null,
        provider: 'ipinfo',
      }
    },
  }
}

export const provider = createProvider()
