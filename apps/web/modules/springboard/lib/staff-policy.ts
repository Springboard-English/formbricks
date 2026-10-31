import type { TOrganizationRole } from "@formbricks/types/memberships";
import type { TSpringboardStaffConfig } from "./config";

/**
 * Staff sign-in policy, as pure functions. Every row of the policy table in SPRINGBOARD.md is one
 * branch here and one test in `staff-policy.test.ts`; the database and Better Auth only feed it.
 *
 * Every reject code starts with `springboard_` so the login page can tell them apart from upstream's.
 */
export const SPRINGBOARD_REJECT_CODES = [
  "springboard_missing_subject",
  "springboard_missing_email",
  "springboard_email_unverified",
  "springboard_domain_not_allowed",
  "springboard_staff_types_unset",
  "springboard_not_staff",
  "springboard_account_inactive",
  "springboard_email_changed",
  "springboard_account_conflict",
  "springboard_no_organization",
  "springboard_multiple_organizations",
  "springboard_invalid_token",
  "springboard_signin_failed",
] as const;

export type TSpringboardRejectCode = (typeof SPRINGBOARD_REJECT_CODES)[number];

export const isSpringboardRejectCode = (code: string | null | undefined): code is TSpringboardRejectCode =>
  (SPRINGBOARD_REJECT_CODES as readonly string[]).includes(code ?? "");

export type TStaffIdentity = {
  sub: string;
  /** Lower-cased. */
  email: string;
  name: string;
  accountType: string;
};

export type TPolicyResult<T> = { ok: true; value: T } | { ok: false; code: TSpringboardRejectCode };

const reject = <T>(code: TSpringboardRejectCode): TPolicyResult<T> => ({ ok: false, code });

export const getEmailDomain = (email: string): string => email.slice(email.lastIndexOf("@") + 1);

/**
 * Decide from the verified id_token claims alone whether this is a Springboard staff member allowed in.
 *
 * Fails closed on anything missing: today's Hydra id_token carries only `sub`, so until the API adds
 * `email` and `email_verified` every sign-in stops here with `springboard_missing_email`.
 */
export const evaluateStaffClaims = (
  claims: Record<string, unknown>,
  config: Pick<TSpringboardStaffConfig, "allowedDomains" | "staffAccountTypes">
): TPolicyResult<TStaffIdentity> => {
  const { sub, email, email_verified: emailVerified, name, account_type: accountType } = claims;

  if (typeof sub !== "string" || sub.length === 0) return reject("springboard_missing_subject");
  if (typeof email !== "string" || !email.includes("@") || emailVerified === undefined) {
    return reject("springboard_missing_email");
  }
  // Strictly `true`: a string "true", 1, or any other truthy value is not a verified address.
  if (emailVerified !== true) return reject("springboard_email_unverified");

  const normalizedEmail = email.trim().toLowerCase();
  if (!config.allowedDomains.includes(getEmailDomain(normalizedEmail))) {
    return reject("springboard_domain_not_allowed");
  }

  if (config.staffAccountTypes.length === 0) return reject("springboard_staff_types_unset");
  if (typeof accountType !== "string" || !config.staffAccountTypes.includes(accountType.toLowerCase())) {
    return reject("springboard_not_staff");
  }

  return {
    ok: true,
    value: {
      sub,
      email: normalizedEmail,
      name: typeof name === "string" && name.trim() ? name.trim() : normalizedEmail.split("@")[0],
      accountType: accountType.toLowerCase(),
    },
  };
};

export type TLinkedUser = { id: string; email: string; isActive: boolean };
export type TEmailUser = {
  id: string;
  isActive: boolean;
  /** `sub`s of Springboard accounts already linked to this user. */
  springboardSubjects: string[];
};

export type TStaffUserDecision =
  | { action: "sign_in"; userId: string }
  | { action: "link"; userId: string }
  | { action: "create" };

/**
 * Decide what to do with a staff identity that already passed `evaluateStaffClaims`.
 *
 * Linking is scoped to this provider and to a verified address, which is the only reason it is safe
 * with upstream's global `accountLinking` left off. The account-takeover rows:
 *
 * - The link is keyed by `sub`. If the IdP's address for that `sub` no longer matches the user's, it is
 *   refused rather than followed: an address change at the IdP must not move or rename a Formbricks
 *   account silently. An admin fixes the address (or offboards) first.
 * - A user who already carries a Springboard link for a DIFFERENT `sub` is not linked a second time:
 *   that is a second IdP account claiming the same address.
 * - Inactive users stay out, whichever way they are found.
 */
export const decideStaffUser = ({
  identity,
  linkedUser,
  emailUser,
}: {
  identity: TStaffIdentity;
  linkedUser: TLinkedUser | null;
  emailUser: TEmailUser | null;
}): TPolicyResult<TStaffUserDecision> => {
  if (linkedUser) {
    if (!linkedUser.isActive) return reject("springboard_account_inactive");
    if (linkedUser.email.toLowerCase() !== identity.email) return reject("springboard_email_changed");
    return { ok: true, value: { action: "sign_in", userId: linkedUser.id } };
  }

  if (emailUser) {
    if (!emailUser.isActive) return reject("springboard_account_inactive");
    if (emailUser.springboardSubjects.some((subject) => subject !== identity.sub)) {
      return reject("springboard_account_conflict");
    }
    return { ok: true, value: { action: "link", userId: emailUser.id } };
  }

  return { ok: true, value: { action: "create" } };
};

export type TPendingInvite = { id: string; organizationId: string; role: TOrganizationRole };
export type TOrganizationTarget = { organizationId: string; role: TOrganizationRole; inviteId?: string };

/**
 * Where a new staff user's membership goes: a pending invite for their address wins (its org and role),
 * otherwise the instance's single organization with the default role. Zero or several organizations
 * means the instance is not the one this policy was written for, so it refuses instead of guessing.
 */
export const decideOrganizationTarget = ({
  invite,
  organizationIds,
  defaultRole,
}: {
  invite: TPendingInvite | null;
  organizationIds: string[];
  defaultRole: TOrganizationRole;
}): TPolicyResult<TOrganizationTarget> => {
  if (invite) {
    return {
      ok: true,
      value: { organizationId: invite.organizationId, role: invite.role, inviteId: invite.id },
    };
  }
  if (organizationIds.length === 0) return reject("springboard_no_organization");
  if (organizationIds.length > 1) return reject("springboard_multiple_organizations");
  return { ok: true, value: { organizationId: organizationIds[0], role: defaultRole } };
};
