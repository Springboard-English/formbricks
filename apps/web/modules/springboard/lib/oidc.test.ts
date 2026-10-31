import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { clearOidcProviderCache, getOidcProvider, parseOidcMetadata, verifyIdToken } from "./oidc";

const ISSUER = "https://auth.springboard.vn/dev";
const AUDIENCE = "respondent-client";

let jwks: ReturnType<typeof createLocalJWKSet>;
let privateKey: CryptoKey;
let otherPrivateKey: CryptoKey;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  const other = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  otherPrivateKey = other.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256" };
  jwks = createLocalJWKSet({ keys: [jwk] });
});

const sign = (claims: Record<string, unknown>, key: CryptoKey = privateKey, exp: string | number = "5m") =>
  new SignJWT({ nonce: "n-1", ...claims })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject("sb-123")
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(key);

const verify = (token: string, overrides: Partial<Parameters<typeof verifyIdToken>[1]> = {}) =>
  verifyIdToken(token, { jwks, issuer: ISSUER, audience: AUDIENCE, nonce: "n-1", ...overrides });

describe("verifyIdToken", () => {
  test("accepts a correctly signed token for this audience, issuer and nonce", async () => {
    const payload = await verify(await sign({ email: "a@springboard.vn" }));
    expect(payload).toMatchObject({ sub: "sb-123", email: "a@springboard.vn" });
  });

  test("rejects a token signed by another key", async () => {
    await expect(verify(await sign({}, otherPrivateKey))).rejects.toThrow();
  });

  test("rejects a tampered payload (signature no longer matches)", async () => {
    const [header, , signature] = (await sign({ email: "a@springboard.vn" })).split(".");
    const forged = Buffer.from(
      JSON.stringify({ iss: ISSUER, aud: AUDIENCE, sub: "attacker", exp: 9999999999, iat: 1, nonce: "n-1" })
    ).toString("base64url");
    await expect(verify(`${header}.${forged}.${signature}`)).rejects.toThrow();
  });

  test("rejects an unsigned (alg: none) token", async () => {
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const body = Buffer.from(
      JSON.stringify({ iss: ISSUER, aud: AUDIENCE, sub: "x", exp: 9999999999, iat: 1, nonce: "n-1" })
    ).toString("base64url");
    await expect(verify(`${header}.${body}.`)).rejects.toThrow();
  });

  test("rejects the wrong audience (the staff client's token on the respondent client)", async () => {
    await expect(verify(await sign({}), { audience: "staff-client" })).rejects.toThrow();
  });

  test("rejects the wrong issuer", async () => {
    await expect(verify(await sign({}), { issuer: "https://auth.springboard.vn" })).rejects.toThrow();
  });

  test("rejects an expired token", async () => {
    await expect(verify(await sign({}, privateKey, Math.floor(Date.now() / 1000) - 60))).rejects.toThrow();
  });

  test("rejects a nonce mismatch (replayed token)", async () => {
    await expect(verify(await sign({ nonce: "other" }))).rejects.toThrow("nonce");
  });
});

describe("discovery", () => {
  afterEach(() => clearOidcProviderCache());

  const document = {
    issuer: `${ISSUER}/`,
    authorization_endpoint: `${ISSUER}/oauth2/auth`,
    token_endpoint: `${ISSUER}/oauth2/token`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  };

  test("accepts the configured issuer, with or without a trailing slash", () => {
    expect(parseOidcMetadata(ISSUER, document).issuer).toBe(`${ISSUER}/`);
  });

  test("refuses a document that names another issuer", () => {
    expect(() => parseOidcMetadata(ISSUER, { ...document, issuer: "https://evil.example" })).toThrow();
  });

  test("refuses a document missing an endpoint", () => {
    expect(() => parseOidcMetadata(ISSUER, { ...document, token_endpoint: undefined })).toThrow();
  });

  test("fetches the well-known document once and caches it", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(JSON.stringify(document)));
    await getOidcProvider(ISSUER, fetchImpl);
    await getOidcProvider(ISSUER, fetchImpl);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][0]).toBe(`${ISSUER}/.well-known/openid-configuration`);
  });

  test("a failed discovery throws instead of verifying against nothing", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response("nope", { status: 503 }));
    await expect(getOidcProvider(ISSUER, fetchImpl)).rejects.toThrow("503");
  });
});
