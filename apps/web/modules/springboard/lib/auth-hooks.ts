import { type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { SPRINGBOARD_PROVIDER_ID } from "./config";

/**
 * Compose Springboard's provider into the Better Auth database hooks without touching upstream's.
 *
 * Upstream's `user.create.before` cannot recognise the `springboard` provider id, so it would treat a
 * Springboard sign-up as a credential sign-up and reject it on a closed instance. This wrapper decides
 * our provider's user creation BEFORE that path and hands every other request to the upstream hook
 * unchanged — same arguments, same return value, same throw.
 *
 * Our decision is "never here": staff users are created by `provisionSpringboardStaffUser` before
 * Better Auth looks them up, and the provider sets `disableSignUp`. Reaching this hook on the
 * Springboard callback means something bypassed that, so it is refused rather than allowed.
 */

type TDatabaseHooks = NonNullable<BetterAuthOptions["databaseHooks"]>;
type TUserCreateBefore = NonNullable<NonNullable<NonNullable<TDatabaseHooks["user"]>["create"]>["before"]>;
type THookContext = Parameters<TUserCreateBefore>[1];

/** True for Better Auth's OAuth callback (`/callback/:id`) when the provider is ours. */
export const isSpringboardCallback = (ctx: THookContext): boolean => {
  if (!ctx) return false;
  const params = (ctx as { params?: Record<string, unknown> }).params;
  const path = ctx.path ?? "";
  return (
    params?.id === SPRINGBOARD_PROVIDER_ID &&
    (path === "/callback/:id" || path === `/callback/${SPRINGBOARD_PROVIDER_ID}`)
  );
};

export const SPRINGBOARD_IMPLICIT_SIGNUP_ERROR_CODE = "springboard_signin_failed";

export const composeUserCreateBefore =
  (upstream: TUserCreateBefore | undefined): TUserCreateBefore =>
  async (user, ctx) => {
    if (isSpringboardCallback(ctx)) {
      throw new APIError("FORBIDDEN", {
        code: SPRINGBOARD_IMPLICIT_SIGNUP_ERROR_CODE,
        message: "Springboard users are provisioned by the Springboard sign-in policy only.",
      });
    }
    return upstream ? upstream(user, ctx) : undefined;
  };

/** `hooks` with only `user.create.before` wrapped; every other hook is the very same function. */
export const withSpringboardDatabaseHooks = <T extends TDatabaseHooks>(hooks: T): T => ({
  ...hooks,
  user: {
    ...hooks.user,
    create: {
      ...hooks.user?.create,
      before: composeUserCreateBefore(hooks.user?.create?.before),
    },
  },
});
