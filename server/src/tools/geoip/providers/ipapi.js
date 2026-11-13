import { safeHttp } from '../../../net/safeHttp.js'

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
      return {
        ip,
        country: data.country_name ?? null,
        region: data.region ?? null,
        city: data.city ?? null,
        latitude: Number.isFinite(data.latitude) ? data.latitude : null,
        longitude: Number.isFinite(data.longitude) ? data.longitude : null,
        asn: data.asn ?? null,
        org: data.org ?? null,
        provider: 'ipapi',
      }
    },
  }
}

export const provider = createProvider()
