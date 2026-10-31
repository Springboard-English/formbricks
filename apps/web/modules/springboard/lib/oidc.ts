import { type JWTPayload, type JWTVerifyGetKey, createRemoteJWKSet, jwtVerify } from "jose";
import { getDiscoveryUrl, normalizeIssuer } from "./config";

/**
 * The slice of the issuer's discovery document Springboard's two OIDC clients use.
 *
 * Written against OpenID Connect Discovery 1.0 and RFC 8414 directly; nothing here is Hydra-specific.
 */
export type TOidcMetadata = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
};

const DISCOVERY_TTL_MS = 10 * 60 * 1000;
const DISCOVERY_TIMEOUT_MS = 5_000;

type TCachedMetadata = { metadata: TOidcMetadata; jwks: JWTVerifyGetKey; expiresAt: number };
const metadataCache = new Map<string, TCachedMetadata>();

const isNonEmptyString = (value: unknown): value is string => typeof value === "string" && value.length > 0;

/**
 * Parse a discovery document, refusing one whose `issuer` is not the configured issuer: a document that
 * names another issuer would let that issuer's tokens through the `iss` check below.
 */
export const parseOidcMetadata = (configuredIssuer: string, document: unknown): TOidcMetadata => {
  if (document === null || typeof document !== "object") {
    throw new Error("OIDC discovery document is not an object");
  }
  const doc = document as Record<string, unknown>;
  const { issuer, authorization_endpoint, token_endpoint, jwks_uri } = doc;
  if (
    !isNonEmptyString(issuer) ||
    !isNonEmptyString(authorization_endpoint) ||
    !isNonEmptyString(token_endpoint) ||
    !isNonEmptyString(jwks_uri)
  ) {
    throw new Error("OIDC discovery document is missing a required endpoint");
  }
  if (normalizeIssuer(issuer) !== normalizeIssuer(configuredIssuer)) {
    throw new Error("OIDC discovery document names a different issuer");
  }
  return { issuer, authorization_endpoint, token_endpoint, jwks_uri };
};

/** Discovery + JWKS for an issuer, cached for ten minutes per process. */
export const getOidcProvider = async (
  configuredIssuer: string,
  fetchImpl: typeof fetch = fetch
): Promise<{ metadata: TOidcMetadata; jwks: JWTVerifyGetKey }> => {
  const key = normalizeIssuer(configuredIssuer);
  const cached = metadataCache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    return cached;
  }

  const response = await fetchImpl(getDiscoveryUrl(key), {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`OIDC discovery failed with status ${response.status}`);
  }
  const metadata = parseOidcMetadata(key, await response.json());
  const entry = {
    metadata,
    jwks: createRemoteJWKSet(new URL(metadata.jwks_uri)),
    expiresAt: Date.now() + DISCOVERY_TTL_MS,
  };
  metadataCache.set(key, entry);
  return entry;
};

/** Test seam: forget cached discovery documents. */
export const clearOidcProviderCache = (): void => metadataCache.clear();

export type TVerifyIdTokenOptions = {
  jwks: JWTVerifyGetKey;
  /** The `issuer` from the discovery document (already checked against the configured one). */
  issuer: string;
  audience: string;
  /** Required for the respondent flow; the staff flow's nonce is checked by Better Auth itself. */
  nonce?: string;
  currentDate?: Date;
};

/**
 * Verify an id_token's signature against the issuer's JWKS, plus `iss`, `aud`, `exp` (and `nbf`/`iat`
 * via jose) and, when given, `nonce`. Asymmetric algorithms only: `alg: none` and HMAC tokens signed
 * with a guessable client secret are refused outright.
 */
export const verifyIdToken = async (idToken: string, options: TVerifyIdTokenOptions): Promise<JWTPayload> => {
  const { payload } = await jwtVerify(idToken, options.jwks, {
    issuer: options.issuer,
    audience: options.audience,
    algorithms: ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"],
    currentDate: options.currentDate,
    requiredClaims: ["sub", "exp", "iat"],
  });
  if (options.nonce !== undefined && payload.nonce !== options.nonce) {
    throw new Error("id_token nonce mismatch");
  }
  return payload;
};
