import { describe, expect, test, vi } from "vitest";
import { composeUserCreateBefore, isSpringboardCallback, withSpringboardDatabaseHooks } from "./auth-hooks";

type TCtx = Parameters<ReturnType<typeof composeUserCreateBefore>>[1];
const ctx = (path: string, id?: string) => ({ path, params: id ? { id } : {} }) as unknown as TCtx;

const user = { email: "a@springboard.vn", name: "A", emailVerified: true } as never;

describe("Springboard database hook composition", () => {
  test("recognises only the springboard OAuth callback", () => {
    expect(isSpringboardCallback(ctx("/callback/:id", "springboard"))).toBe(true);
    expect(isSpringboardCallback(ctx("/callback/:id", "openid"))).toBe(false);
    expect(isSpringboardCallback(ctx("/sign-up/email"))).toBe(false);
    expect(isSpringboardCallback(null as unknown as TCtx)).toBe(false);
  });

  test.each([
    ["the upstream SSO provider", ctx("/callback/:id", "openid")],
    ["google", ctx("/callback/:id", "google")],
    ["email sign-up", ctx("/sign-up/email")],
    ["an in-process call with no context", null as unknown as TCtx],
  ])("hands %s to the upstream hook unchanged", async (_label, hookCtx) => {
    const upstreamResult = { data: { isBootstrapAdmin: "bootstrapAdmin" } };
    const upstream = vi.fn().mockResolvedValue(upstreamResult);

    await expect(composeUserCreateBefore(upstream)(user, hookCtx)).resolves.toBe(upstreamResult);
    expect(upstream).toHaveBeenCalledWith(user, hookCtx);
  });

  test("passes an upstream rejection through untouched", async () => {
    const rejection = new Error("Signup is disabled on this instance.");
    const upstream = vi.fn().mockRejectedValue(rejection);
    await expect(composeUserCreateBefore(upstream)(user, ctx("/sign-up/email"))).rejects.toBe(rejection);
  });

  test("decides the springboard callback itself, before the upstream hook", async () => {
    const upstream = vi.fn();
    await expect(
      composeUserCreateBefore(upstream)(user, ctx("/callback/:id", "springboard"))
    ).rejects.toMatchObject({ body: { code: "springboard_signin_failed" } });
    expect(upstream).not.toHaveBeenCalled();
  });

  test("wraps only user.create.before; every other upstream hook is the same function", () => {
    const hooks = {
      user: {
        create: { before: vi.fn(), after: vi.fn() },
        update: { before: vi.fn() },
      },
      account: { create: { before: vi.fn() } },
    };
    const composed = withSpringboardDatabaseHooks(hooks);

    expect(composed.user.create.after).toBe(hooks.user.create.after);
    expect(composed.user.update).toBe(hooks.user.update);
    expect(composed.account).toBe(hooks.account);
    expect(composed.user.create.before).not.toBe(hooks.user.create.before);
  });
});
