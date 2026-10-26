import "server-only";
import { APIError } from "better-auth/api";
import type { GenericOAuthConfig } from "better-auth/plugins";
import { logger } from "@formbricks/logger";
import { WEBAPP_URL } from "@/lib/constants";
import { SPRINGBOARD_PROVIDER_ID, type TSpringboardStaffConfig, getDiscoveryUrl } from "./config";
import { getOidcProvider, verifyIdToken } from "./oidc";
import { getSpringboardStaffConfig } from "./runtime-config";
import { type TSpringboardRejectCode, evaluateStaffClaims, getEmailDomain } from "./staff-policy";
import { provisionSpringboardStaffUser } from "./staff-provisioning";

/**
 * "Sign in with Springboard" as a Better Auth genericOAuth provider (built from the plugin's public
 * options: discovery, PKCE, client secret on the token endpoint, a pinned redirect URI).
 *
 * The policy runs in `getUserInfo`, which Better Auth calls after it has checked state and PKCE,
 * exchanged the code, and verified the id_token against the discovery JWKS and the nonce. A refusal
 * redirects to the login page with `?error=springboard_*`, which the login form explains.
 */

export const getSpringboardCallbackUrl = (): string =>
  `${WEBAPP_URL.replace(/\/+$/, "")}/api/auth/oauth2/callback/${SPRINGBOARD_PROVIDER_ID}`;

/** The redirect Better Auth turns into a 302: the same shape its own `ctx.redirect` throws. */
export const springboardRejectRedirect = (code: TSpringboardRejectCode): APIError =>
  new APIError("FOUND", undefined, new Headers({ location: `${WEBAPP_URL}/auth/login?error=${code}` }));

export const createSpringboardGetUserInfo =
  (config: TSpringboardStaffConfig, provision = provisionSpringboardStaffUser) =>
  async (tokens: { idToken?: string }) => {
    if (!tokens.idToken) {
      logger.warn({ code: "springboard_invalid_token" }, "Springboard sign-in returned no id_token");
      throw springboardRejectRedirect("springboard_invalid_token");
    }

    // Better Auth has already verified it when discovery succeeded at boot; this second check also
    // covers the case where it could not, and pins the audience to the STAFF client.
    let claims: Record<string, unknown>;
    try {
      const { metadata, jwks } = await getOidcProvider(config.issuer);
      claims = await verifyIdToken(tokens.idToken, {
        jwks,
        issuer: metadata.issuer,
        audience: config.clientId,
      });
    } catch (error) {
      logger.warn({ error, code: "springboard_invalid_token" }, "Springboard id_token failed verification");
      throw springboardRejectRedirect("springboard_invalid_token");
    }

    const evaluation = evaluateStaffClaims(claims, config);
    if (!evaluation.ok) {
      const email = typeof claims.email === "string" ? claims.email : "";
      logger.warn(
        { code: evaluation.code, emailDomain: email ? getEmailDomain(email) : undefined },
        "Springboard sign-in refused by policy"
      );
      throw springboardRejectRedirect(evaluation.code);
    }

    const provisioning = await provision(evaluation.value, config);
    if (!provisioning.ok) {
      logger.warn({ code: provisioning.code }, "Springboard sign-in refused by policy");
      throw springboardRejectRedirect(provisioning.code);
    }

    const { sub, email, name } = evaluation.value;
    return { id: sub, sub, email, emailVerified: true, name };
  };

/** `[]` when staff sign-in is not configured, so spreading it into genericOAuth changes nothing. */
export const getSpringboardGenericOAuthConfig = (
  config: TSpringboardStaffConfig | null = getSpringboardStaffConfig()
): GenericOAuthConfig[] => {
  if (!config) return [];
  return [
    {
      providerId: SPRINGBOARD_PROVIDER_ID,
      name: "Springboard",
      discoveryUrl: getDiscoveryUrl(config.issuer),
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      // Hydra's default `token_endpoint_auth_method`; register the client with it.
      tokenEndpointAuth: { method: "client_secret_basic" },
      scopes: ["openid", "email", "profile"],
      pkce: true,
      redirectURI: getSpringboardCallbackUrl(),
      // A stable account namespace even when discovery is down at boot, and the value our own
      // provisioning writes into `Account.issuer`, so Better Auth finds the link it wrote.
      accountIssuer: config.issuer,
      // Users are created by `provisionSpringboardStaffUser`, never implicitly by Better Auth.
      disableSignUp: true,
      // The IdP must not be able to rewrite a user's address; a changed address is refused instead.
      overrideUserInfo: false,
      getUserInfo: createSpringboardGetUserInfo(config),
      mapProfileToUser: (profile) => ({ email: String(profile.email), emailVerified: true }),
    },
  ];
};
