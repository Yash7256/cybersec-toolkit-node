import { z } from 'zod'

export const schema = z.object({
  target: z.string().trim().min(1).max(253),
  max_hops: z.coerce.number().int().min(1).max(64).default(30),
})

export const inputShape = Object.freeze({
  target: { type: 'string', required: true, description: 'Hostname or IP address to trace' },
  max_hops: { type: 'integer', minimum: 1, maximum: 64, default: 30 },
})
