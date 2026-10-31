import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, test, vi } from "vitest";
import type { TSpringboardRespondentConfig } from "./config";
import type { TOidcMetadata } from "./oidc";
import type { TRespondentFlowState } from "./respondent-cookie";
import {
  buildRespondentAuthorization,
  completeRespondentCallback,
  createPkceChallenge,
  identityFromClaims,
  sanitizeReturnTo,
} from "./respondent-flow";

const ISSUER = "https://auth.springboard.vn";
const config: TSpringboardRespondentConfig = {
  issuer: ISSUER,
  clientId: "respondent-client",
  clientSecret: "respondent-secret",
  cookieSecret: "c".repeat(32),
};
const metadata: TOidcMetadata = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/oauth2/auth`,
  token_endpoint: `${ISSUER}/oauth2/token`,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
};
const REDIRECT = "https://forms.springboard.vn/api/springboard/respondent/callback";
const flow: TRespondentFlowState = {
  surveyId: "survey1",
  state: "state-1",
  nonce: "nonce-1",
  codeVerifier: "verifier-1",
  returnTo: "/s/survey1?suId=abc",
};

let privateKey: CryptoKey;
let otherKey: CryptoKey;
let jwks: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  otherKey = (await generateKeyPair("RS256")).privateKey;
  jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), alg: "RS256" }] });
});

const idToken = (claims: Record<string, unknown>, key: CryptoKey = privateKey) =>
  new SignJWT({ nonce: "nonce-1", ...claims })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(ISSUER)
    .setAudience("respondent-client")
    .setSubject("sb-42")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);

const tokenEndpoint = (body: unknown, status = 200) =>
  vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status }));

const callback = (fetchImpl: typeof fetch, query = "code=c1&state=state-1", flowState = flow) =>
  completeRespondentCallback({
    config,
    metadata,
    jwks,
    redirectUri: REDIRECT,
    flow: flowState,
    query: new URLSearchParams(query),
    fetchImpl,
  });

describe("respondent authorization request", () => {
  test("uses the respondent client, openid email profile, state, nonce and S256 PKCE", async () => {
    const { authorizationUrl, flow: created } = await buildRespondentAuthorization({
      config,
      metadata,
      redirectUri: REDIRECT,
      surveyId: "survey1",
      returnTo: "/s/survey1?suId=abc&suToken=t&source=mail",
    });
    const url = new URL(authorizationUrl);
    expect(url.origin + url.pathname).toBe(metadata.authorization_endpoint);
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      response_type: "code",
      client_id: "respondent-client",
      redirect_uri: REDIRECT,
      scope: "openid email profile",
      state: created.state,
      nonce: created.nonce,
      code_challenge: await createPkceChallenge(created.codeVerifier),
      code_challenge_method: "S256",
    });
    expect(created.returnTo).toBe("/s/survey1?suId=abc&suToken=t&source=mail");
  });

  test.each([
    ["https://evil.example/s/survey1", "/s/survey1"],
    ["//evil.example/s/survey1", "/s/survey1"],
    ["/s/other-survey", "/s/survey1"],
    ["/auth/login", "/s/survey1"],
    ["/s/survey1?lang=vi", "/s/survey1?lang=vi"],
  ])("return path %s becomes %s", (input, expected) => {
    expect(sanitizeReturnTo("survey1", input)).toBe(expected);
  });
});

describe("respondent callback", () => {
  test("exchanges the code with PKCE and client_secret_basic, and keeps only the identity", async () => {
    const fetchImpl = tokenEndpoint({
      access_token: "at",
      id_token: await idToken({ email: "Student@Gmail.com", email_verified: false, account_type: "student" }),
    });

    await expect(callback(fetchImpl)).resolves.toEqual({
      ok: true,
      identity: { email: "student@gmail.com", emailVerified: false, sub: "sb-42", accountType: "student" },
    });
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(metadata.token_endpoint);
    expect(init.headers.authorization).toBe(
      `Basic ${Buffer.from("respondent-client:respondent-secret").toString("base64")}`
    );
    expect(Object.fromEntries(init.body as URLSearchParams)).toEqual({
      grant_type: "authorization_code",
      code: "c1",
      redirect_uri: REDIRECT,
      code_verifier: "verifier-1",
    });
  });

  test("a state that does not match the browser's flow cookie is refused before any exchange", async () => {
    const fetchImpl = tokenEndpoint({});
    await expect(callback(fetchImpl, "code=c1&state=forged")).resolves.toEqual({
      ok: false,
      error: "respondent_invalid_state",
    });
    await expect(callback(fetchImpl, "code=c1&state=state-1", null as never)).resolves.toMatchObject({
      ok: false,
      error: "respondent_invalid_state",
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  test("a tampered id_token signature is refused", async () => {
    const fetchImpl = tokenEndpoint({
      id_token: await idToken({ email: "a@b.vn", email_verified: true }, otherKey),
    });
    await expect(callback(fetchImpl)).resolves.toEqual({ ok: false, error: "respondent_invalid_token" });
  });

  test("an id_token for another request (nonce) is refused", async () => {
    const fetchImpl = tokenEndpoint({
      id_token: await idToken({ email: "a@b.vn", email_verified: true, nonce: "x" }),
    });
    await expect(callback(fetchImpl)).resolves.toEqual({ ok: false, error: "respondent_invalid_token" });
  });

  test("a sub-only id_token still proves the account, with no address on file", async () => {
    const fetchImpl = tokenEndpoint({ id_token: await idToken({}) });
    await expect(callback(fetchImpl)).resolves.toEqual({
      ok: true,
      identity: { email: "", emailVerified: false, sub: "sb-42", accountType: "unknown" },
    });
  });

  test("an IdP error or failed exchange is refused", async () => {
    await expect(callback(tokenEndpoint({}), "error=access_denied&state=state-1")).resolves.toMatchObject({
      error: "respondent_idp_error",
    });
    await expect(callback(tokenEndpoint({ error: "invalid_grant" }, 400))).resolves.toMatchObject({
      error: "respondent_token_exchange_failed",
    });
  });
});

describe("identityFromClaims", () => {
  test("the account is the identity: an unverified address is recorded, not refused", () => {
    expect(identityFromClaims({ sub: "s", email: "a@b.vn", email_verified: false })).toEqual({
      ok: true,
      identity: { email: "a@b.vn", emailVerified: false, sub: "s", accountType: "unknown" },
    });
    expect(
      identityFromClaims({
        sub: "s",
        email: "a@springboard.vn",
        email_verified: true,
        account_type: "Employee",
      })
    ).toEqual({
      ok: true,
      identity: { email: "a@springboard.vn", emailVerified: true, sub: "s", accountType: "employee" },
    });
  });

  test("only a missing sub is refused", () => {
    expect(identityFromClaims({ email: "a@b.vn", email_verified: true })).toEqual({
      ok: false,
      error: "respondent_invalid_token",
    });
  });
});
