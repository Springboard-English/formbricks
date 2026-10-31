import "server-only";
import { NextResponse } from "next/server";
import { z } from "zod";
import { logger } from "@formbricks/logger";
import { TooManyRequestsError } from "@formbricks/types/errors";
import { applyIPRateLimit } from "@/modules/core/rate-limit/helpers";
import {
  isAuthorizedSpringboardRequest,
  listActiveUserEmails,
  offboardSpringboardUser,
} from "@/modules/springboard/lib/offboard";
import { getSpringboardOffboardSecret } from "@/modules/springboard/lib/runtime-config";

/**
 * `POST /api/springboard/offboard` and `GET /api/springboard/users`, called by Springboard's API with
 * `Authorization: Bearer <SPRINGBOARD_OFFBOARD_SECRET>`. Both 404 while the secret is unset, so the
 * routes do not exist on an instance that has not opted in.
 *
 * Rate-limited per client IP BEFORE the secret is checked, so the secret cannot be brute-forced.
 */

const RATE_LIMIT = { interval: 60, allowedPerInterval: 60, namespace: "springboard:offboard" };

const ZOffboardBody = z.object({ email: z.email().max(320) });

const json = (body: unknown, status = 200) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store" } });

const guard = async (request: Request): Promise<Response | null> => {
  const secret = getSpringboardOffboardSecret();
  if (!secret) return json({ error: "not_found" }, 404);

  try {
    await applyIPRateLimit(RATE_LIMIT);
  } catch (error) {
    if (error instanceof TooManyRequestsError) return json({ error: "too_many_requests" }, 429);
    throw error;
  }

  if (!isAuthorizedSpringboardRequest(request.headers.get("authorization"), secret)) {
    return json({ error: "unauthorized" }, 401);
  }
  return null;
};

export const handleOffboard = async (request: Request): Promise<Response> => {
  const rejection = await guard(request);
  if (rejection) return rejection;

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json({ error: "bad_request" }, 400);
  }
  const parsed = ZOffboardBody.safeParse(body);
  if (!parsed.success) return json({ error: "bad_request" }, 400);

  try {
    const result = await offboardSpringboardUser(parsed.data.email);
    if (result.status === "last_owner") {
      return json({ error: "last_owner", message: "Refusing to deactivate the last active owner." }, 409);
    }
    // Identical for a user deactivated now, one already inactive and an address nobody has.
    return json({ status: "ok" });
  } catch (error) {
    logger.error({ error }, "Springboard offboarding failed");
    return json({ error: "internal_server_error" }, 500);
  }
};

export const handleListUsers = async (request: Request): Promise<Response> => {
  const rejection = await guard(request);
  if (rejection) return rejection;

  try {
    return json({ emails: await listActiveUserEmails() });
  } catch (error) {
    logger.error({ error }, "Springboard user listing failed");
    return json({ error: "internal_server_error" }, 500);
  }
};
