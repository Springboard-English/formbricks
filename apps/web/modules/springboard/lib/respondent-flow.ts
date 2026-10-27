import { randomBytes } from "node:crypto";
import type { TSpringboardRespondentConfig } from "./config";
import { type TOidcMetadata, verifyIdToken } from "./oidc";
import type { TRespondentFlowState, TRespondentIdentity } from "./respondent-cookie";

/**
 * A minimal OpenID Connect authorization-code client for survey respondents, on the RESPONDENT
 * Hydra client. Deliberately separate from Better Auth: respondents (students, parents, staff) are
 * not Formbricks users, so this never creates a user, an account or a session — it only proves a
 * Springboard account to a single survey for two hours.
 *
 * Written from OpenID Connect Core 1.0 and RFC 7636 (PKCE): `state` binds the callback to this
 * browser, `nonce` binds the id_token to this request, the verifier binds the code to this client.
 */

// `profile` carries `account_type`; without it every respondent would read as "unknown".
export const RESPONDENT_SCOPES = "openid email profile";

export type TRespondentFlowError =
  | "respondent_invalid_state"
  | "respondent_idp_error"
  | "respondent_token_exchange_failed"
  | "respondent_invalid_token";

const randomToken = (): string => randomBytes(32).toString("base64url");

export const createPkceChallenge = async (verifier: string): Promise<string> => {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return Buffer.from(digest).toString("base64url");
};

/**
 * Only a same-origin path back to this survey's own link (`/s/<id>`, any query) is accepted, so the
 * callback cannot be turned into an open redirect.
 */
export const sanitizeReturnTo = (surveyId: string, returnTo: string | null | undefined): string => {
  const fallback = `/s/${surveyId}`;
  if (!returnTo || !returnTo.startsWith("/") || returnTo.startsWith("//") || returnTo.includes("\\")) {
    return fallback;
  }
  try {
    const url = new URL(returnTo, "https://placeholder.invalid");
    if (url.origin !== "https://placeholder.invalid" || url.pathname !== fallback) return fallback;
    return `${url.pathname}${url.search}`;
  } catch {
    return fallback;
  }
};

export const buildRespondentAuthorization = async ({
  config,
  metadata,
  redirectUri,
  surveyId,
  returnTo,
}: {
  config: TSpringboardRespondentConfig;
  metadata: TOidcMetadata;
  redirectUri: string;
  surveyId: string;
  returnTo: string;
}): Promise<{ authorizationUrl: string; flow: TRespondentFlowState }> => {
  const flow: TRespondentFlowState = {
    surveyId,
    state: randomToken(),
    nonce: randomToken(),
    codeVerifier: randomToken(),
    returnTo: sanitizeReturnTo(surveyId, returnTo),
  };
  const url = new URL(metadata.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", RESPONDENT_SCOPES);
  url.searchParams.set("state", flow.state);
  url.searchParams.set("nonce", flow.nonce);
  url.searchParams.set("code_challenge", await createPkceChallenge(flow.codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  return { authorizationUrl: url.toString(), flow };
};

export type TRespondentCallbackResult =
  | { ok: true; identity: TRespondentIdentity }
  | { ok: false; error: TRespondentFlowError };

/**
 * Pull the respondent identity out of verified claims. The identity is the Springboard account
 * (`sub`), proven by the signed token. The email is the address on file: Springboard marks it
 * verified only for staff mailboxes it created, so `email_verified: false` is normal for students
 * and parents and is recorded, never refused.
 */
export const identityFromClaims = (
  claims: Record<string, unknown>
): { ok: true; identity: TRespondentIdentity } | { ok: false; error: TRespondentFlowError } => {
  const { sub, email, email_verified: emailVerified, account_type: accountType } = claims;
  if (typeof sub !== "string" || !sub) return { ok: false, error: "respondent_invalid_token" };
  return {
    ok: true,
    identity: {
      email: typeof email === "string" && email.includes("@") ? email.trim().toLowerCase() : "",
      emailVerified: emailVerified === true,
      sub,
      accountType: typeof accountType === "string" && accountType ? accountType.toLowerCase() : "unknown",
    },
  };
};

export const completeRespondentCallback = async ({
  config,
  metadata,
  jwks,
  redirectUri,
  flow,
  query,
  fetchImpl = fetch,
}: {
  config: TSpringboardRespondentConfig;
  metadata: TOidcMetadata;
  jwks: Parameters<typeof verifyIdToken>[1]["jwks"];
  redirectUri: string;
  flow: TRespondentFlowState | null;
  query: URLSearchParams;
  fetchImpl?: typeof fetch;
}): Promise<TRespondentCallbackResult> => {
  // `state` first: nothing from an unbound callback is trusted, not even its error.
  if (!flow || !query.get("state") || query.get("state") !== flow.state) {
    return { ok: false, error: "respondent_invalid_state" };
  }
  if (query.get("error")) return { ok: false, error: "respondent_idp_error" };
  const code = query.get("code");
  if (!code) return { ok: false, error: "respondent_idp_error" };

  let idToken: unknown;
  try {
    const response = await fetchImpl(metadata.token_endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
        // client_secret_basic (RFC 6749 §2.3.1): form-encode, then base64.
        authorization: `Basic ${Buffer.from(
          `${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: flow.codeVerifier,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return { ok: false, error: "respondent_token_exchange_failed" };
    idToken = ((await response.json()) as { id_token?: unknown }).id_token;
  } catch {
    return { ok: false, error: "respondent_token_exchange_failed" };
  }
  if (typeof idToken !== "string") return { ok: false, error: "respondent_invalid_token" };

  let claims: Record<string, unknown>;
  try {
    claims = await verifyIdToken(idToken, {
      jwks,
      issuer: metadata.issuer,
      audience: config.clientId,
      nonce: flow.nonce,
    });
  } catch {
    return { ok: false, error: "respondent_invalid_token" };
  }

  // The access and id tokens go out of scope here: only the three identity fields are kept.
  return identityFromClaims(claims);
};
