// Pure helpers + event handlers for Clerk user sync. No I/O beyond the repos
// passed in, so the logic is unit-testable and the webhook route stays thin.

export function primaryEmail(clerkUser) {
  const addresses = clerkUser.email_addresses ?? clerkUser.emailAddresses ?? []
  const primaryId =
    clerkUser.primary_email_address_id ?? clerkUser.primaryEmailAddressId ?? null
  const primary = addresses.find((entry) => entry.id === primaryId)
  const chosen = primary ?? addresses[0]
  return chosen ? (chosen.email_address ?? chosen.emailAddress ?? null) : null
}

export function tierFromMetadata(metadata) {
  return metadata?.tier === 'paid' ? 'PAID' : 'FREE'
}

function extractUser(data) {
  return {
    clerkUserId: data.id,
    email: primaryEmail(data),
    tier: tierFromMetadata(data.public_metadata ?? data.publicMetadata),
  }
}

export async function handleClerkEvent(event, { userRepo, auditRepo }) {
  switch (event.type) {
    case 'user.created': {
      const { clerkUserId, email, tier } = extractUser(event.data)
      const user = await userRepo.upsertFromClerk({ clerkUserId, email, tier })
      await auditRepo.log({
        actorId: user.id,
        action: 'user.created',
        entityType: 'user',
        entityId: user.id,
      })
      return { handled: true }
    }

    case 'user.updated': {
      const { clerkUserId, email, tier } = extractUser(event.data)
      const existing = await userRepo.findByClerkId(clerkUserId)
      // Out-of-order safe: an update can arrive before the create webhook.
      const user = existing
        ? await userRepo.updateFromClerk({ clerkUserId, email, tier })
        : await userRepo.upsertFromClerk({ clerkUserId, email, tier })

      if (existing && existing.tier !== tier) {
        await auditRepo.log({
          actorId: user.id,
          action: 'tier.changed',
          entityType: 'user',
          entityId: user.id,
          metadata: { from: existing.tier, to: tier },
        })
      }
      return { handled: true }
    }

    case 'user.deleted': {
      const existing = await userRepo.findByClerkId(event.data.id)
      if (existing) {
        await userRepo.softDelete(existing.id)
        await auditRepo.log({
          actorId: existing.id,
          action: 'user.deleted',
          entityType: 'user',
          entityId: existing.id,
        })
      }
      return { handled: true }
    }

    default:
      return { handled: false }
  }
}
