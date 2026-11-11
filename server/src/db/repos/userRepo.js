import { prisma } from '../client.js'

export async function findByClerkId(clerkUserId) {
  const user = await prisma.user.findUnique({ where: { clerkUserId } })
  return user
}

export async function upsertFromClerk({ clerkUserId, email }) {
  const normalizedEmail = email.toLowerCase()
  const user = await prisma.user.upsert({
    where: { clerkUserId },
    create: { clerkUserId, email: normalizedEmail },
    update: { email: normalizedEmail },
  })
  return user
}

export async function softDelete(id) {
  const user = await prisma.user.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false, email: null },
  })
  return user
}
