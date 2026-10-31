import "server-only";
import { prisma } from "@formbricks/database";
import { Prisma } from "@formbricks/database/prisma";
import { logger } from "@formbricks/logger";
import { reconcileOrganizationMembership } from "@/lib/authzed/organization-membership";
import { runPostCommitProjection } from "@/lib/authzed/projection-boundary";
import { constantTimeEqual, hashSha256 } from "@/lib/crypto";
import { revokeUserSessionsExcept } from "@/modules/auth/lib/session-revocation";
import { SPRINGBOARD_PROVIDER_ID } from "./config";

/**
 * Offboarding: Springboard calls this when a staff account is deactivated, so their Formbricks
 * access ends within minutes instead of whenever someone remembers.
 *
 * Deactivation uses the core's own mechanism, `User.isActive = false`, which every sign-in path
 * (`better-auth-active-user-gate.ts`), every session read (`session.ts`, `proxy-session.ts`) and the
 * MCP server already honour. The user row, their surveys and their responses are kept.
 */

/**
 * `Authorization: Bearer <secret>`, compared in constant time. Both sides are hashed first so the
 * comparison never depends on the secret's length either.
 */
export const isAuthorizedSpringboardRequest = (
  authorizationHeader: string | null,
  secret: string | null
): boolean => {
  if (!secret || !authorizationHeader) return false;
  const match = /^Bearer\s+(.+)$/i.exec(authorizationHeader.trim());
  if (!match) return false;
  return constantTimeEqual(hashSha256(match[1]), hashSha256(secret), "hex");
};

export type TOffboardResult =
  /** Same answer for "deactivated now", "already inactive" and "no such user": no existence oracle. */
  { status: "ok" } | { status: "last_owner" };

class LastActiveOwnerError extends Error {}

const MAX_SERIALIZABLE_ATTEMPTS = 3;

const isSerializationFailure = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2034";

/**
 * Deactivate under SERIALIZABLE so two offboardings of the last two owners cannot both pass the
 * owner check (the same reasoning as the v2 users API's last-owner guard).
 */
const deactivateUnlessLastActiveOwner = async (userId: string): Promise<string[]> => {
  for (let attempt = 1; ; attempt++) {
    try {
      return await prisma.$transaction(
        async (tx) => {
          const ownedOrganizations = await tx.membership.findMany({
            where: { userId, role: "owner" },
            select: { organizationId: true },
          });
          for (const { organizationId } of ownedOrganizations) {
            const otherActiveOwners = await tx.membership.count({
              where: { organizationId, role: "owner", userId: { not: userId }, user: { isActive: true } },
            });
            if (otherActiveOwners === 0) throw new LastActiveOwnerError();
          }
          await tx.user.update({ where: { id: userId }, data: { isActive: false } });
          const memberships = await tx.membership.findMany({
            where: { userId },
            select: { organizationId: true },
          });
          return memberships.map((membership) => membership.organizationId);
        },
        { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
      );
    } catch (error) {
      if (isSerializationFailure(error) && attempt < MAX_SERIALIZABLE_ATTEMPTS) continue;
      throw error;
    }
  }
};

/** Every session, in Redis and in the database, whichever store a given session lives in. */
const revokeAllSessions = async (userId: string): Promise<void> => {
  // By token from the database rows: removes each from Redis and the DB.
  await revokeUserSessionsExcept({ userId });
  // By user: sweeps Redis' active-session list and any row the first pass raced with.
  const { auth } = await import("@/modules/auth/lib/auth");
  const ctx = await auth.$context;
  await ctx.internalAdapter.deleteUserSessions(userId);
};

export const offboardSpringboardUser = async (email: string): Promise<TOffboardResult> => {
  const user = await prisma.user.findUnique({
    where: { email: email.trim().toLowerCase() },
    select: { id: true, isActive: true },
  });
  if (!user) return { status: "ok" };

  if (user.isActive) {
    let organizationIds: string[];
    try {
      organizationIds = await deactivateUnlessLastActiveOwner(user.id);
    } catch (error) {
      if (error instanceof LastActiveOwnerError) {
        logger.warn({ userId: user.id }, "Springboard offboarding refused: last active owner");
        return { status: "last_owner" };
      }
      throw error;
    }
    for (const organizationId of organizationIds) {
      await runPostCommitProjection("springboard_offboard_membership", () =>
        reconcileOrganizationMembership(organizationId, user.id)
      );
    }
  }

  // Repeated on every call, so a retry also finishes a previous call that failed half-way.
  await revokeAllSessions(user.id);
  await prisma.account.deleteMany({ where: { userId: user.id, provider: SPRINGBOARD_PROVIDER_ID } });

  logger.info({ userId: user.id, wasActive: user.isActive }, "Springboard user offboarded");
  return { status: "ok" };
};

/** Active users' addresses, for Springboard's daily reconciliation. Nothing else is exposed. */
export const listActiveUserEmails = async (): Promise<string[]> => {
  const users = await prisma.user.findMany({
    where: { isActive: true },
    select: { email: true },
    orderBy: { email: "asc" },
  });
  return users.map((user) => user.email);
};
