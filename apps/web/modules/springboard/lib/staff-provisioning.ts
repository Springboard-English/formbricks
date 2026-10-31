import "server-only";
import { prisma } from "@formbricks/database";
import { Prisma } from "@formbricks/database/prisma";
import { logger } from "@formbricks/logger";
import { reconcileOrganizationMembership } from "@/lib/authzed/organization-membership";
import { runPostCommitProjection } from "@/lib/authzed/projection-boundary";
import { createMembership } from "@/lib/membership/service";
import { SPRINGBOARD_PROVIDER_ID, type TSpringboardStaffConfig } from "./config";
import {
  type TPolicyResult,
  type TStaffIdentity,
  decideOrganizationTarget,
  decideStaffUser,
  getEmailDomain,
} from "./staff-policy";

/**
 * The database half of staff sign-in: find, link or create the Formbricks user for a staff identity
 * that already passed the claims policy, so that Better Auth's own callback only ever has to sign an
 * already-linked account in.
 *
 * Doing it here rather than in Better Auth's `user.create` hook is what keeps this provider's
 * decisions in our code: upstream's create hook is the licensed SSO module's, and it rejects every
 * new user on a closed instance. With the user and its link written first, Better Auth finds the
 * account by `(issuer, sub)` and never reaches user creation (`disableSignUp` makes sure of it).
 *
 * New users are written exactly the way core invite acceptance does: the user, account and
 * membership in one Postgres transaction, then the membership projected to SpiceDB after commit —
 * a Postgres-only membership would authorise nothing in Formbricks 6.
 */

export type TStaffProvisioningResult = TPolicyResult<{ userId: string; created: boolean; linked: boolean }>;

const isUniqueViolation = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002";

const findPendingInvite = (email: string) =>
  prisma.invite.findFirst({
    where: { email: { equals: email, mode: "insensitive" }, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: "desc" },
    select: { id: true, organizationId: true, role: true },
  });

export const provisionSpringboardStaffUser = async (
  identity: TStaffIdentity,
  config: Pick<TSpringboardStaffConfig, "issuer" | "defaultRole">,
  attempt = 0
): Promise<TStaffProvisioningResult> => {
  const [linkedAccount, emailUser] = await Promise.all([
    prisma.account.findFirst({
      where: { provider: SPRINGBOARD_PROVIDER_ID, providerAccountId: identity.sub },
      select: { user: { select: { id: true, email: true, isActive: true } } },
    }),
    prisma.user.findUnique({
      where: { email: identity.email },
      select: {
        id: true,
        isActive: true,
        accounts: { where: { provider: SPRINGBOARD_PROVIDER_ID }, select: { providerAccountId: true } },
      },
    }),
  ]);

  const decision = decideStaffUser({
    identity,
    linkedUser: linkedAccount?.user ?? null,
    emailUser: emailUser
      ? {
          id: emailUser.id,
          isActive: emailUser.isActive,
          springboardSubjects: emailUser.accounts.map((account) => account.providerAccountId),
        }
      : null,
  });
  if (!decision.ok) return decision;

  const accountData = {
    provider: SPRINGBOARD_PROVIDER_ID,
    providerAccountId: identity.sub,
    issuer: config.issuer,
    type: "oidc",
  };

  switch (decision.value.action) {
    case "sign_in":
      return { ok: true, value: { userId: decision.value.userId, created: false, linked: false } };

    case "link": {
      try {
        await prisma.account.create({ data: { ...accountData, userId: decision.value.userId } });
      } catch (error) {
        // Two tabs finishing the same first sign-in: the other one already wrote this exact link.
        if (!isUniqueViolation(error)) throw error;
      }
      logger.info(
        { userId: decision.value.userId, emailDomain: getEmailDomain(identity.email) },
        "Linked Springboard account to existing user"
      );
      return { ok: true, value: { userId: decision.value.userId, created: false, linked: true } };
    }

    case "create": {
      const [invite, organizations] = await Promise.all([
        findPendingInvite(identity.email),
        prisma.organization.findMany({ select: { id: true }, take: 2 }),
      ]);
      const target = decideOrganizationTarget({
        invite,
        organizationIds: organizations.map((organization) => organization.id),
        defaultRole: config.defaultRole,
      });
      if (!target.ok) return target;
      const { organizationId, role, inviteId } = target.value;

      let userId: string;
      try {
        userId = await prisma.$transaction(async (tx) => {
          const user = await tx.user.create({
            data: {
              email: identity.email,
              name: identity.name,
              emailVerified: true,
              // `openid` rather than `email`: every reader of this column treats non-`email` as "the IdP
              // owns this identity" — no password reset, no profile email/name edits, deletion by email
              // link. That is the behaviour a Springboard-managed account needs, and no new enum value
              // (so no migration) is required. See SPRINGBOARD.md.
              identityProvider: "openid",
              identityProviderAccountId: identity.sub,
              accounts: { create: accountData },
            },
            select: { id: true },
          });
          await createMembership(
            organizationId,
            user.id,
            { role, accepted: true },
            { projection: "deferred", transaction: tx }
          );
          if (inviteId) {
            await tx.invite.delete({ where: { id: inviteId } });
          }
          return user.id;
        });
      } catch (error) {
        if (!isUniqueViolation(error) || attempt > 0) throw error;
        // A concurrent first sign-in created the same user; re-decide once against what it wrote.
        return provisionSpringboardStaffUser(identity, config, attempt + 1);
      }

      await runPostCommitProjection("springboard_staff_membership", () =>
        reconcileOrganizationMembership(organizationId, userId)
      );
      logger.info(
        { userId, organizationId, role, viaInvite: Boolean(inviteId) },
        "Provisioned Springboard staff user"
      );
      return { ok: true, value: { userId, created: true, linked: true } };
    }
  }
};
