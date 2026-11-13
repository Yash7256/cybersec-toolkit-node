import { safeHttp } from '../../../net/safeHttp.js'
import { continentName, flagEmoji } from './_normalize.js'

export function createProvider({ client = safeHttp } = {}) {
  return {
    name: 'ipapi',
    async lookup(ip, { signal } = {}) {
      const response = await client.request(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
        mode: 'trusted',
        allowHosts: ['ipapi.co'],
        maxBytes: 128 * 1024,
        signal,
      })
      const data = JSON.parse(response.body.toString('utf8'))
      if (data.error) throw new Error('provider failed')
      const countryCode = data.country_code ?? null
      return {
        ip,
        country: data.country_name ?? null,
        country_code: countryCode,
        continent: continentName(data.continent_code),
        continent_code: data.continent_code ?? null,
        region: data.region ?? null,
        city: data.city ?? null,
        postal: data.postal ?? null,
        latitude: Number.isFinite(data.latitude) ? data.latitude : null,
        longitude: Number.isFinite(data.longitude) ? data.longitude : null,
        timezone: data.timezone ?? null,
        utc_offset: data.utc_offset ?? null,
        flag_emoji: flagEmoji(countryCode),
        calling_code: data.country_calling_code ?? null,
        asn: data.asn ?? null,
        org: data.org ?? null,
        isp: null,
        asn_domain: null,
        is_proxy: null,
        is_hosting: null,
        is_vpn: null,
        is_tor: null,
        provider: 'ipapi',
      }
    },
  }
}

export const provider = createProvider()
