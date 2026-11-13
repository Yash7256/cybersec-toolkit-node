import { privacyDetected, expiryStatus, riskIndicators } from './privacy.js'

function event(data, action) { return data.events?.find((x) => x.eventAction === action)?.eventDate ?? null }
function vcard(entity, field) { return entity?.vcardArray?.[1]?.find((x) => x[0] === field)?.[3] ?? null }
export function normalizeRdap(domain, data) {
  const expiration = event(data, 'expiration'); const days = expiration ? Math.ceil((Date.parse(expiration) - Date.now()) / 86400000) : null
  const registrar = data.entities?.find((x) => x.roles?.includes('registrar'))
  const names = (data.nameservers ?? []).map((x) => x.ldhName ?? x.unicodeName).filter(Boolean).map((x) => x.toLowerCase()).filter((x, i, a) => a.indexOf(x) === i)
  const privacy = privacyDetected([vcard(registrar, 'fn'), ...(data.entities ?? []).map((x) => vcard(x, 'org'))])
  return { target: domain, domain, available: true, registrar: vcard(registrar, 'fn'), creation_date: event(data, 'registration'), expiration_date: expiration, updated_date: event(data, 'last changed'), name_servers: names, status: data.status ?? [], dnssec: data.secureDNS?.delegationSigned ?? null, privacy_protected: privacy, days_until_expiry: days, expiry_status: expiryStatus(days), risk_indicators: riskIndicators({ privacy, status: data.status ?? [], days }), summary: null, error: null, rdap_available: true, normalized: true, rdap: data }
}
