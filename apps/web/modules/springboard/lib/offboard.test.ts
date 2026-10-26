import { beforeEach, describe, expect, test, vi } from "vitest";
import { prisma } from "@formbricks/database";
import { reconcileOrganizationMembership } from "@/lib/authzed/organization-membership";
import { revokeUserSessionsExcept } from "@/modules/auth/lib/session-revocation";
import { isAuthorizedSpringboardRequest, listActiveUserEmails, offboardSpringboardUser } from "./offboard";

const { deleteUserSessions } = vi.hoisted(() => ({ deleteUserSessions: vi.fn() }));

const tx = {
  membership: { findMany: vi.fn(), count: vi.fn() },
  user: { update: vi.fn() },
};

vi.mock("@formbricks/database", () => ({
  prisma: {
    user: { findUnique: vi.fn(), findMany: vi.fn() },
    account: { deleteMany: vi.fn() },
    $transaction: vi.fn(),
  },
}));
// vitestSetup.ts stubs `createHash` to a constant; the secret comparison needs the real one.
vi.unmock("crypto");
vi.mock("@formbricks/logger", () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock("@/lib/authzed/organization-membership", () => ({ reconcileOrganizationMembership: vi.fn() }));
vi.mock("@/modules/auth/lib/session-revocation", () => ({ revokeUserSessionsExcept: vi.fn() }));
vi.mock("@/modules/auth/lib/auth", () => ({
  auth: { $context: Promise.resolve({ internalAdapter: { deleteUserSessions } }) },
}));

const SECRET = "s".repeat(40);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(prisma.$transaction).mockImplementation((async (fn: (client: typeof tx) => unknown) =>
    fn(tx)) as never);
  tx.membership.findMany.mockImplementation(async ({ where }: { where: { role?: string } }) =>
    where.role === "owner" ? [] : [{ organizationId: "org1" }]
  );
  tx.membership.count.mockResolvedValue(1);
});

describe("isAuthorizedSpringboardRequest", () => {
  test("accepts exactly the bearer secret", () => {
    expect(isAuthorizedSpringboardRequest(`Bearer ${SECRET}`, SECRET)).toBe(true);
  });

  test.each([
    ["no header", null],
    ["the wrong secret", `Bearer ${"x".repeat(40)}`],
    ["a prefix of the secret", `Bearer ${SECRET.slice(0, 10)}`],
    ["the secret without the Bearer scheme", SECRET],
    ["Basic auth", `Basic ${SECRET}`],
  ])("rejects %s", (_label, header) => {
    expect(isAuthorizedSpringboardRequest(header, SECRET)).toBe(false);
  });

  test("rejects everything when no secret is configured", () => {
    expect(isAuthorizedSpringboardRequest("Bearer ", null)).toBe(false);
  });
});

describe("offboardSpringboardUser", () => {
  test("deactivates, projects to SpiceDB, revokes sessions in both stores and removes the link", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u1", isActive: true } as never);

    await expect(offboardSpringboardUser(" Linh@Springboard.vn ")).resolves.toEqual({ status: "ok" });

    expect(prisma.user.findUnique).toHaveBeenCalledWith({
      where: { email: "linh@springboard.vn" },
      select: { id: true, isActive: true },
    });
    expect(tx.user.update).toHaveBeenCalledWith({ where: { id: "u1" }, data: { isActive: false } });
    expect(reconcileOrganizationMembership).toHaveBeenCalledWith("org1", "u1");
    expect(revokeUserSessionsExcept).toHaveBeenCalledWith({ userId: "u1" });
    expect(deleteUserSessions).toHaveBeenCalledWith("u1");
    expect(prisma.account.deleteMany).toHaveBeenCalledWith({
      where: { userId: "u1", provider: "springboard" },
    });
  });

  test("keeps the user row: it never deletes the user, their surveys or responses", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u1", isActive: true } as never);
    await offboardSpringboardUser("linh@springboard.vn");
    expect(Object.keys(prisma.user)).not.toContain("delete");
    expect(tx.user.update.mock.calls[0][0].data).toEqual({ isActive: false });
  });

  test("is idempotent: an already-inactive user gets the same answer and a fresh session sweep", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u1", isActive: false } as never);

    await expect(offboardSpringboardUser("linh@springboard.vn")).resolves.toEqual({ status: "ok" });
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(revokeUserSessionsExcept).toHaveBeenCalledWith({ userId: "u1" });
    expect(deleteUserSessions).toHaveBeenCalledWith("u1");
  });

  test("answers an unknown address exactly like a known one, and touches nothing", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue(null);

    await expect(offboardSpringboardUser("nobody@springboard.vn")).resolves.toEqual({ status: "ok" });
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(revokeUserSessionsExcept).not.toHaveBeenCalled();
  });

  test("refuses to deactivate the last active owner", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u1", isActive: true } as never);
    tx.membership.findMany.mockResolvedValue([{ organizationId: "org1" }]);
    tx.membership.count.mockResolvedValue(0);

    await expect(offboardSpringboardUser("owner@springboard.vn")).resolves.toEqual({ status: "last_owner" });
    expect(tx.membership.count).toHaveBeenCalledWith({
      where: { organizationId: "org1", role: "owner", userId: { not: "u1" }, user: { isActive: true } },
    });
    expect(tx.user.update).not.toHaveBeenCalled();
    expect(revokeUserSessionsExcept).not.toHaveBeenCalled();
  });

  test("an owner with another active owner beside them is deactivated", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u1", isActive: true } as never);
    tx.membership.findMany.mockResolvedValue([{ organizationId: "org1" }]);
    tx.membership.count.mockResolvedValue(1);

    await expect(offboardSpringboardUser("owner@springboard.vn")).resolves.toEqual({ status: "ok" });
    expect(tx.user.update).toHaveBeenCalled();
  });
});

describe("listActiveUserEmails", () => {
  test("lists active users' addresses only", async () => {
    vi.mocked(prisma.user.findMany).mockResolvedValue([{ email: "a@springboard.vn" }] as never);
    await expect(listActiveUserEmails()).resolves.toEqual(["a@springboard.vn"]);
    expect(prisma.user.findMany).toHaveBeenCalledWith({
      where: { isActive: true },
      select: { email: true },
      orderBy: { email: "asc" },
    });
  });
});
