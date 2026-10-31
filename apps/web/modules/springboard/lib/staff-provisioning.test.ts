import { beforeEach, describe, expect, test, vi } from "vitest";
import { prisma } from "@formbricks/database";
import { Prisma } from "@formbricks/database/prisma";
import { reconcileOrganizationMembership } from "@/lib/authzed/organization-membership";
import { createMembership } from "@/lib/membership/service";
import type { TStaffIdentity } from "./staff-policy";
import { provisionSpringboardStaffUser } from "./staff-provisioning";

const tx = {
  user: { create: vi.fn() },
  invite: { delete: vi.fn() },
};

vi.mock("@formbricks/database", () => ({
  prisma: {
    account: { findFirst: vi.fn(), create: vi.fn() },
    user: { findUnique: vi.fn() },
    invite: { findFirst: vi.fn() },
    organization: { findMany: vi.fn() },
    $transaction: vi.fn(),
  },
}));
vi.mock("@formbricks/logger", () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock("@/lib/membership/service", () => ({ createMembership: vi.fn() }));
vi.mock("@/lib/authzed/organization-membership", () => ({ reconcileOrganizationMembership: vi.fn() }));

const identity: TStaffIdentity = {
  sub: "sb-123",
  email: "linh@springboard.vn",
  name: "Linh",
  accountType: "employee",
};
const config = { issuer: "https://auth.springboard.vn", defaultRole: "member" as const };

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(prisma.account.findFirst).mockResolvedValue(null);
  vi.mocked(prisma.user.findUnique).mockResolvedValue(null);
  vi.mocked(prisma.invite.findFirst).mockResolvedValue(null);
  vi.mocked(prisma.organization.findMany).mockResolvedValue([{ id: "org1" }] as never);
  vi.mocked(prisma.$transaction).mockImplementation((async (fn: (client: typeof tx) => unknown) =>
    fn(tx)) as never);
  tx.user.create.mockResolvedValue({ id: "new-user" });
});

describe("provisionSpringboardStaffUser", () => {
  test("an already-linked user is signed in with no writes", async () => {
    vi.mocked(prisma.account.findFirst).mockResolvedValue({
      user: { id: "u1", email: "linh@springboard.vn", isActive: true },
    } as never);

    await expect(provisionSpringboardStaffUser(identity, config)).resolves.toEqual({
      ok: true,
      value: { userId: "u1", created: false, linked: false },
    });
    expect(prisma.account.create).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  test("an existing user is linked with a springboard account under the configured issuer", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u1", isActive: true, accounts: [] } as never);

    const result = await provisionSpringboardStaffUser(identity, config);

    expect(result).toEqual({ ok: true, value: { userId: "u1", created: false, linked: true } });
    expect(prisma.account.create).toHaveBeenCalledWith({
      data: {
        userId: "u1",
        provider: "springboard",
        providerAccountId: "sb-123",
        issuer: "https://auth.springboard.vn",
        type: "oidc",
      },
    });
  });

  test("an inactive existing user is refused and not linked", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u1", isActive: false, accounts: [] } as never);

    await expect(provisionSpringboardStaffUser(identity, config)).resolves.toEqual({
      ok: false,
      code: "springboard_account_inactive",
    });
    expect(prisma.account.create).not.toHaveBeenCalled();
  });

  test("a new user gets user + account + membership in one transaction, then the SpiceDB projection", async () => {
    const result = await provisionSpringboardStaffUser(identity, config);

    expect(result).toEqual({ ok: true, value: { userId: "new-user", created: true, linked: true } });
    expect(tx.user.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        email: "linh@springboard.vn",
        emailVerified: true,
        identityProvider: "openid",
        identityProviderAccountId: "sb-123",
        accounts: {
          create: expect.objectContaining({ provider: "springboard", providerAccountId: "sb-123" }),
        },
      }),
      select: { id: true },
    });
    expect(createMembership).toHaveBeenCalledWith(
      "org1",
      "new-user",
      { role: "member", accepted: true },
      { projection: "deferred", transaction: tx }
    );
    expect(reconcileOrganizationMembership).toHaveBeenCalledWith("org1", "new-user");
    // Projection strictly after the Postgres commit.
    expect(vi.mocked(reconcileOrganizationMembership).mock.invocationCallOrder[0]).toBeGreaterThan(
      vi.mocked(prisma.$transaction).mock.invocationCallOrder[0]
    );
  });

  test("a pending invite decides the org and role and is consumed", async () => {
    vi.mocked(prisma.invite.findFirst).mockResolvedValue({
      id: "inv1",
      organizationId: "org-invited",
      role: "manager",
    } as never);

    await provisionSpringboardStaffUser(identity, config);

    expect(createMembership).toHaveBeenCalledWith(
      "org-invited",
      "new-user",
      { role: "manager", accepted: true },
      expect.anything()
    );
    expect(tx.invite.delete).toHaveBeenCalledWith({ where: { id: "inv1" } });
  });

  test.each([
    [[], "springboard_no_organization"],
    [[{ id: "a" }, { id: "b" }], "springboard_multiple_organizations"],
  ])("refuses to create anyone with organizations %j", async (organizations, code) => {
    vi.mocked(prisma.organization.findMany).mockResolvedValue(organizations as never);

    await expect(provisionSpringboardStaffUser(identity, config)).resolves.toEqual({ ok: false, code });
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  test("a concurrent first sign-in is re-decided once against what the other request wrote", async () => {
    vi.mocked(prisma.$transaction).mockRejectedValueOnce(
      new Prisma.PrismaClientKnownRequestError("dup", { code: "P2002", clientVersion: "x" })
    );
    vi.mocked(prisma.account.findFirst)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ user: { id: "u-other", email: identity.email, isActive: true } } as never);

    await expect(provisionSpringboardStaffUser(identity, config)).resolves.toEqual({
      ok: true,
      value: { userId: "u-other", created: false, linked: false },
    });
  });
});
