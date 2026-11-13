import { safeHttp } from '../../../net/safeHttp.js'

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
      return {
        ip: data.ip,
        country: data.country ?? null,
        region: data.region ?? null,
        city: data.city ?? null,
        latitude: Number.isFinite(data.latitude) ? data.latitude : null,
        longitude: Number.isFinite(data.longitude) ? data.longitude : null,
        asn: data.connection?.asn ? `AS${data.connection.asn}` : null,
        org: data.connection?.org ?? null,
        provider: 'ipwhois',
      }
    },
  }
}

export const provider = createProvider()
