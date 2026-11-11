import { prisma } from '../client.js'

// Claim an event id atomically. Returns:
//   { claimed: true,  duplicate: false } -> process it
//   { claimed: false, duplicate: true  } -> already processed, skip
//   { claimed: false, duplicate: false } -> previous attempt failed, retry
export async function claim({ id, source, eventType }) {
  const inserted = await prisma.$queryRaw`
    INSERT INTO webhook_events (id, source, event_type)
    VALUES (${id}, ${source}, ${eventType})
    ON CONFLICT (id) DO NOTHING
    RETURNING id
  `
  if (inserted.length > 0) {
    return { claimed: true, duplicate: false }
  }

  const existing = await prisma.webhookEvent.findUnique({
    where: { id },
    select: { processedAt: true },
  })
  return { claimed: false, duplicate: Boolean(existing?.processedAt) }
}

export async function markProcessed(id) {
  await prisma.webhookEvent.update({
    where: { id },
    data: { processedAt: new Date(), error: null },
  })
}

export async function markFailed(id, message) {
  await prisma.webhookEvent.update({
    where: { id },
    data: {
      processedAt: null,
      error: String(message ?? 'unknown error').slice(0, 1000),
    },
  })
}
