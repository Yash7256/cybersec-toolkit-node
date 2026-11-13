import net from 'node:net'
import { z } from 'zod'

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

export function validBaseDomain(value) {
  if (typeof value !== 'string') return false
  const domain = value.trim()
  if (domain.length === 0 || domain.length > 253) return false
  if (/\s/.test(domain)) return false
  if (/[@/\\?#%:]/.test(domain)) return false
  const normalized = domain.replace(/\.$/, '').toLowerCase()
  if (normalized.length === 0 || net.isIP(normalized) !== 0) return false
  if (!normalized.includes('.')) return false
  return normalized.split('.').every((label) => LABEL.test(label))
}

export const schema = z.object({
  domain: z
    .string()
    .trim()
    .min(1)
    .max(253)
    .refine(validBaseDomain, { message: 'domain must be a valid base hostname, not an IP address' })
    .transform((value) => value.replace(/\.$/, '').toLowerCase()),
  wordlist: z.enum(['small', 'medium', 'large']).default('small'),
  strictness: z.enum(['off', 'low', 'medium', 'high']).default('medium'),
})

export const inputShape = Object.freeze({
  domain: { type: 'string', required: true, description: 'Base domain to enumerate' },
  wordlist: { type: 'string', enum: ['small', 'medium', 'large'], default: 'small' },
  strictness: { type: 'string', enum: ['off', 'low', 'medium', 'high'], default: 'medium' },
})
