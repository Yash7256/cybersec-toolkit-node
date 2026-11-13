import { safeHttp } from '../../../net/safeHttp.js'

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
      return {
        ip: data.ip ?? ip,
        country: data.country ?? null,
        region: data.region ?? null,
        city: data.city ?? null,
        latitude: Number.isFinite(latitude) ? latitude : null,
        longitude: Number.isFinite(longitude) ? longitude : null,
        asn: String(data.org ?? '').match(/AS\d+/i)?.[0] ?? null,
        org: data.org ?? null,
        provider: 'ipinfo',
      }
    },
  }
}

export const provider = createProvider()
