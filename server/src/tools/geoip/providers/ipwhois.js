import { safeHttp } from '../../../net/safeHttp.js'
import { boolOrNull, flagEmoji } from './_normalize.js'

export function createProvider({ client = safeHttp } = {}) {
  return {
    name: 'ipwhois',
    async lookup(ip, { signal } = {}) {
      const response = await client.request(`https://ipwho.is/${encodeURIComponent(ip)}`, {
        mode: 'trusted',
        allowHosts: ['ipwho.is'],
        maxBytes: 128 * 1024,
        signal,
      })
      const data = JSON.parse(response.body.toString('utf8'))
      if (data.success === false) throw new Error('provider failed')
      const countryCode = data.country_code ?? null
      return {
        ip: data.ip ?? ip,
        country: data.country ?? null,
        country_code: countryCode,
        continent: data.continent ?? null,
        continent_code: data.continent_code ?? null,
        region: data.region ?? null,
        city: data.city ?? null,
        postal: data.postal ?? null,
        latitude: Number.isFinite(data.latitude) ? data.latitude : null,
        longitude: Number.isFinite(data.longitude) ? data.longitude : null,
        timezone: data.timezone?.id ?? null,
        utc_offset: data.timezone?.utc ?? null,
        flag_emoji: data.flag?.emoji ?? flagEmoji(countryCode),
        calling_code: data.calling_code ?? null,
        asn: data.connection?.asn ? `AS${data.connection.asn}` : null,
        org: data.connection?.org ?? null,
        isp: data.connection?.isp ?? null,
        asn_domain: data.connection?.domain ?? null,
        is_proxy: data.security ? boolOrNull(data.security.proxy) : null,
        is_hosting: data.security ? boolOrNull(data.security.hosting) : null,
        is_vpn: data.security ? boolOrNull(data.security.vpn) : null,
        is_tor: data.security ? boolOrNull(data.security.tor) : null,
        provider: 'ipwhois',
      }
    },
  }
}

export const provider = createProvider()
