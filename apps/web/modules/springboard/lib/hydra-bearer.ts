import "server-only";
import { type JWTVerifyGetKey, decodeJwt, jwtVerify } from "jose";
import { prisma } from "@formbricks/database";
import { logger } from "@formbricks/logger";
import type { Session } from "@formbricks/types/auth";
import { parseApiKeyV2 } from "@/lib/crypto";
import { getBearerTokenFromHeaders } from "@/modules/api/lib/api-key-auth";
import { SPRINGBOARD_PROVIDER_ID, type TSpringboardHydraBearerConfig, normalizeIssuer } from "./config";
import { readTokenScopes, requiredHydraBearerScope } from "./hydra-bearer-policy";
import { getOidcProvider } from "./oidc";
import { getSpringboardHydraBearerConfig } from "./runtime-config";

/**
 * Hydra access tokens on `/api/v3` (SPRINGBOARD.md, "Hydra bearer tokens").
 *
 * Springboard's API swaps its caller's token at Hydra (RFC 7523 jwt-bearer) for one whose audience is
 * this instance, and sends it as `Authorization: Bearer`. Here it is verified against the staff issuer's
 * JWKS, checked for the scope the route needs, and turned into a session for the Formbricks user linked
 * to its `sub`. From there Formbricks' own roles decide, exactly as for a cookie sign-in.
 */

/**
 * `absent`: not a Hydra token, so the request goes on to API-key auth. `refused`: a Hydra token that
 * failed a check, answered 401 with no fallback. `session`: the linked user.
 */
export type THydraBearerResult =
  | { kind: "absent" }
  | { kind: "refused"; reason: string }
  | { kind: "session"; session: Session };

type TLinkedUser = { id: string; email: string; isActive: boolean };

export type THydraBearerDeps = {
  getJwks: (issuer: string) => Promise<JWTVerifyGetKey>;
  findLinkedUser: (sub: string) => Promise<TLinkedUser | null>;
  now?: Date;
};

type THydraBearerRequest = { token: string | null; method: string; pathname: string };

const ABSENT: THydraBearerResult = { kind: "absent" };
const refused = (reason: string): THydraBearerResult => ({ kind: "refused", reason });

/** The unverified `iss`, or `null` when the token is not a JWT at all. */
const peekIssuer = (token: string): string | null => {
  try {
    const { iss } = decodeJwt(token);
    return typeof iss === "string" ? normalizeIssuer(iss) : null;
  } catch {
    return null;
  }
};

export const resolveHydraBearer = async (
  request: THydraBearerRequest,
  config: TSpringboardHydraBearerConfig | null,
  deps: THydraBearerDeps
): Promise<THydraBearerResult> => {
  const { token } = request;
  if (!config || !token || parseApiKeyV2(token)) return ABSENT;
  // Only a token that claims our issuer is ours to judge; anything else keeps today's behaviour.
  if (peekIssuer(token) !== config.issuer) return ABSENT;

  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(token, await deps.getJwks(config.issuer), {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"],
      currentDate: deps.now,
      requiredClaims: ["sub", "exp", "iat"],
    }));
  } catch {
    return refused("token did not verify");
  }

  const scope = requiredHydraBearerScope(request.method, request.pathname);
  if (!scope) return refused("route is not open to Springboard tokens");
  if (!readTokenScopes(payload).includes(scope)) return refused(`token lacks ${scope}`);

  const sub = String(payload.sub);
  const user = await deps.findLinkedUser(sub);
  if (!user) return refused("no Formbricks account is linked to this Springboard account");
  if (!user.isActive) return refused("the linked Formbricks account is inactive");

  return {
    kind: "session",
    session: {
      user: { id: user.id, email: user.email, isActive: true },
      expires: new Date(Number(payload.exp) * 1000).toISOString(),
    },
  };
};

const defaultDeps: THydraBearerDeps = {
  getJwks: async (issuer) => (await getOidcProvider(issuer)).jwks,
  findLinkedUser: async (sub) => {
    const account = await prisma.account.findFirst({
      where: { provider: SPRINGBOARD_PROVIDER_ID, providerAccountId: sub },
      select: { user: { select: { id: true, email: true, isActive: true } } },
    });
    return account?.user ?? null;
  },
};

type TRequestLike = { headers: Pick<Headers, "get">; method: string; nextUrl: { pathname: string } };

/** The v3 wrapper's entry point. Logs every refusal with its reason, never the token. */
export const authenticateSpringboardBearer = async (req: TRequestLike): Promise<THydraBearerResult> => {
  const result = await resolveHydraBearer(
    { token: getBearerTokenFromHeaders(req.headers), method: req.method, pathname: req.nextUrl.pathname },
    getSpringboardHydraBearerConfig(),
    defaultDeps
  );
  if (result.kind === "refused") {
    logger.info(
      { reason: result.reason, method: req.method, path: req.nextUrl.pathname },
      "Springboard bearer refused"
    );
  }
  return result;
};
