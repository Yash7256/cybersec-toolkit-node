import { prisma } from '../client.js'

const normalizeEmail = (email) => (email ? email.toLowerCase() : null)

export async function findByClerkId(clerkUserId) {
  const user = await prisma.user.findUnique({ where: { clerkUserId } })
  return user
}

export async function findById(id) {
  const user = await prisma.user.findUnique({ where: { id } })
  return user
}

export async function upsertFromClerk({ clerkUserId, email, tier }) {
  const normalizedEmail = normalizeEmail(email)
  const shared = { email: normalizedEmail, ...(tier ? { tier } : {}) }
  const user = await prisma.user.upsert({
    where: { clerkUserId },
    create: { clerkUserId, ...shared },
    update: shared,
  })
  return user
}

export async function updateFromClerk({ clerkUserId, email, tier }) {
  const normalizedEmail = normalizeEmail(email)
  const user = await prisma.user.update({
    where: { clerkUserId },
    data: { email: normalizedEmail, ...(tier ? { tier } : {}) },
  })
  return user
}

export async function setTier(clerkUserId, tier) {
  return prisma.user.update({ where: { clerkUserId }, data: { tier } })
}

export async function softDelete(id) {
  const user = await prisma.user.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false, email: null },
  })
  return user
}
