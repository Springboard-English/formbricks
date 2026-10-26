import { describe, expect, test } from "vitest";
import { getOAuthErrorVariant } from "@/modules/auth/lib/oauth-error";
import {
  SPRINGBOARD_REJECT_CODES,
  type TStaffIdentity,
  decideOrganizationTarget,
  decideStaffUser,
  evaluateStaffClaims,
} from "./staff-policy";

const config = { allowedDomains: ["springboard.vn"], staffAccountTypes: ["employee"] };

const claims = {
  sub: "sb-123",
  email: "Linh@Springboard.vn",
  email_verified: true,
  name: "Linh Nguyen",
  account_type: "employee",
};

const identity: TStaffIdentity = {
  sub: "sb-123",
  email: "linh@springboard.vn",
  name: "Linh Nguyen",
  accountType: "employee",
};

describe("evaluateStaffClaims", () => {
  test("allows a verified staff address on an allowed domain", () => {
    expect(evaluateStaffClaims(claims, config)).toEqual({ ok: true, value: identity });
  });

  test.each([
    ["no sub", { ...claims, sub: undefined }, "springboard_missing_subject"],
    // Today's Hydra id_token: `sub` only. Must fail closed.
    ["sub only (today's token)", { sub: "sb-123" }, "springboard_missing_email"],
    ["email without email_verified", { ...claims, email_verified: undefined }, "springboard_missing_email"],
    ["unverified email", { ...claims, email_verified: false }, "springboard_email_unverified"],
    [
      'email_verified as the string "true"',
      { ...claims, email_verified: "true" },
      "springboard_email_unverified",
    ],
    ["wrong domain", { ...claims, email: "linh@gmail.com" }, "springboard_domain_not_allowed"],
    [
      "look-alike subdomain",
      { ...claims, email: "linh@evil.springboard.vn" },
      "springboard_domain_not_allowed",
    ],
    ["student account", { ...claims, account_type: "student" }, "springboard_not_staff"],
    ["parent account", { ...claims, account_type: "parent" }, "springboard_not_staff"],
    ["no account_type", { ...claims, account_type: undefined }, "springboard_not_staff"],
  ])("refuses %s", (_label, input, code) => {
    expect(evaluateStaffClaims(input as Record<string, unknown>, config)).toEqual({ ok: false, code });
  });

  test("refuses everyone while the staff account-type list is unset", () => {
    expect(evaluateStaffClaims(claims, { ...config, staffAccountTypes: [] })).toEqual({
      ok: false,
      code: "springboard_staff_types_unset",
    });
  });

  test("falls back to the address's local part when the token has no name", () => {
    const result = evaluateStaffClaims({ ...claims, name: undefined }, config);
    expect(result.ok && result.value.name).toBe("linh");
  });
});

describe("decideStaffUser", () => {
  test("signs in the user an existing link belongs to", () => {
    expect(
      decideStaffUser({
        identity,
        linkedUser: { id: "u1", email: "linh@springboard.vn", isActive: true },
        emailUser: null,
      })
    ).toEqual({ ok: true, value: { action: "sign_in", userId: "u1" } });
  });

  test("links an existing user found by verified address", () => {
    expect(
      decideStaffUser({
        identity,
        linkedUser: null,
        emailUser: { id: "u1", isActive: true, springboardSubjects: [] },
      })
    ).toEqual({ ok: true, value: { action: "link", userId: "u1" } });
  });

  test("creates a user when nobody has the address", () => {
    expect(decideStaffUser({ identity, linkedUser: null, emailUser: null })).toEqual({
      ok: true,
      value: { action: "create" },
    });
  });

  test("takeover: the IdP changed the address of a linked sub", () => {
    expect(
      decideStaffUser({
        identity: { ...identity, email: "someone.else@springboard.vn" },
        linkedUser: { id: "u1", email: "linh@springboard.vn", isActive: true },
        emailUser: { id: "u2", isActive: true, springboardSubjects: [] },
      })
    ).toEqual({ ok: false, code: "springboard_email_changed" });
  });

  test("takeover: a second IdP account claims an address already linked to another sub", () => {
    expect(
      decideStaffUser({
        identity: { ...identity, sub: "sb-999" },
        linkedUser: null,
        emailUser: { id: "u1", isActive: true, springboardSubjects: ["sb-123"] },
      })
    ).toEqual({ ok: false, code: "springboard_account_conflict" });
  });

  test("inactive users stay blocked, found by link or by address", () => {
    expect(
      decideStaffUser({
        identity,
        linkedUser: { id: "u1", email: "linh@springboard.vn", isActive: false },
        emailUser: null,
      })
    ).toEqual({ ok: false, code: "springboard_account_inactive" });
    expect(
      decideStaffUser({
        identity,
        linkedUser: null,
        emailUser: { id: "u1", isActive: false, springboardSubjects: [] },
      })
    ).toEqual({ ok: false, code: "springboard_account_inactive" });
  });
});

describe("decideOrganizationTarget", () => {
  test("a pending invite wins, with its own org and role", () => {
    expect(
      decideOrganizationTarget({
        invite: { id: "inv1", organizationId: "org2", role: "manager" },
        organizationIds: ["org1", "org2"],
        defaultRole: "member",
      })
    ).toEqual({ ok: true, value: { organizationId: "org2", role: "manager", inviteId: "inv1" } });
  });

  test("otherwise the single organization with the default role", () => {
    expect(
      decideOrganizationTarget({ invite: null, organizationIds: ["org1"], defaultRole: "member" })
    ).toEqual({ ok: true, value: { organizationId: "org1", role: "member" } });
  });

  test("zero or several organizations refuse instead of guessing", () => {
    expect(decideOrganizationTarget({ invite: null, organizationIds: [], defaultRole: "member" })).toEqual({
      ok: false,
      code: "springboard_no_organization",
    });
    expect(
      decideOrganizationTarget({ invite: null, organizationIds: ["a", "b"], defaultRole: "member" })
    ).toEqual({ ok: false, code: "springboard_multiple_organizations" });
  });
});

describe("login page error codes", () => {
  test("every Springboard reject code gets the Springboard alert, upstream codes keep theirs", () => {
    for (const code of SPRINGBOARD_REJECT_CODES) {
      expect(getOAuthErrorVariant(code)).toBe("springboard_denied");
    }
    expect(getOAuthErrorVariant("account_not_linked")).toBe("account_not_linked");
    expect(getOAuthErrorVariant("something_new")).toBe("generic");
  });
});
