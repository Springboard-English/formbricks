import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, test, vi } from "vitest";
import type { TSpringboardStaffConfig } from "./config";
import { getOidcProvider } from "./oidc";
import {
  createSpringboardGetUserInfo,
  getSpringboardCallbackUrl,
  getSpringboardGenericOAuthConfig,
} from "./staff-provider";

vi.mock("@/lib/constants", () => ({ WEBAPP_URL: "https://forms.springboard.vn" }));
vi.mock("@formbricks/logger", () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock("./runtime-config", () => ({ getSpringboardStaffConfig: vi.fn(() => null) }));
vi.mock("./staff-provisioning", () => ({ provisionSpringboardStaffUser: vi.fn() }));
vi.mock("./oidc", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./oidc")>()),
  getOidcProvider: vi.fn(),
}));

const ISSUER = "https://auth.springboard.vn";
const config: TSpringboardStaffConfig = {
  issuer: ISSUER,
  clientId: "staff-client",
  clientSecret: "staff-secret",
  allowedDomains: ["springboard.vn"],
  defaultRole: "member",
  staffAccountTypes: ["employee"],
};

let privateKey: CryptoKey;
let jwks: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), alg: "RS256" }] });
});

beforeEach(() => {
  vi.mocked(getOidcProvider).mockResolvedValue({
    metadata: {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/oauth2/auth`,
      token_endpoint: `${ISSUER}/oauth2/token`,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    },
    jwks,
  });
});

const idToken = (claims: Record<string, unknown>, audience = "staff-client") =>
  new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setSubject("sb-123")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);

const staffClaims = {
  email: "linh@springboard.vn",
  email_verified: true,
  name: "Linh",
  account_type: "employee",
};

const expectRedirect = async (promise: Promise<unknown>, code: string) => {
  const error = (await promise.catch((caught: unknown) => caught)) as {
    statusCode: number;
    headers: Headers;
  };
  expect(error.statusCode).toBe(302);
  expect(error.headers.get("location")).toBe(`https://forms.springboard.vn/auth/login?error=${code}`);
};

describe("Springboard provider config", () => {
  test("is empty when staff sign-in is not configured", () => {
    expect(getSpringboardGenericOAuthConfig(null)).toEqual([]);
  });

  test("uses discovery, PKCE, the three scopes, client-secret auth and the pinned callback", () => {
    const [provider] = getSpringboardGenericOAuthConfig(config);
    expect(provider).toMatchObject({
      providerId: "springboard",
      discoveryUrl: "https://auth.springboard.vn/.well-known/openid-configuration",
      clientId: "staff-client",
      clientSecret: "staff-secret",
      tokenEndpointAuth: { method: "client_secret_basic" },
      scopes: ["openid", "email", "profile"],
      pkce: true,
      redirectURI: "https://forms.springboard.vn/api/auth/oauth2/callback/springboard",
      accountIssuer: ISSUER,
      disableSignUp: true,
      overrideUserInfo: false,
    });
    expect(provider.providerId).not.toBe("openid");
    expect(getSpringboardCallbackUrl()).toBe(provider.redirectURI);
  });
});

describe("Springboard getUserInfo", () => {
  test("returns the verified identity once policy and provisioning allow it", async () => {
    const provision = vi.fn().mockResolvedValue({ ok: true, value: { userId: "u1" } });
    const getUserInfo = createSpringboardGetUserInfo(config, provision);

    await expect(getUserInfo({ idToken: await idToken(staffClaims) })).resolves.toEqual({
      id: "sb-123",
      sub: "sb-123",
      email: "linh@springboard.vn",
      emailVerified: true,
      name: "Linh",
    });
    expect(provision).toHaveBeenCalledWith(expect.objectContaining({ sub: "sb-123" }), config);
  });

  test("today's sub-only token fails closed and creates nobody", async () => {
    const provision = vi.fn();
    await expectRedirect(
      createSpringboardGetUserInfo(config, provision)({ idToken: await idToken({}) }),
      "springboard_missing_email"
    );
    expect(provision).not.toHaveBeenCalled();
  });

  test("a token issued to another client (the respondent client) is refused", async () => {
    const provision = vi.fn();
    await expectRedirect(
      createSpringboardGetUserInfo(config, provision)({ idToken: await idToken(staffClaims, "respondent") }),
      "springboard_invalid_token"
    );
    expect(provision).not.toHaveBeenCalled();
  });

  test("no id_token is refused", async () => {
    await expectRedirect(createSpringboardGetUserInfo(config, vi.fn())({}), "springboard_invalid_token");
  });

  test("a provisioning refusal is surfaced with its own code", async () => {
    const provision = vi.fn().mockResolvedValue({ ok: false, code: "springboard_no_organization" });
    await expectRedirect(
      createSpringboardGetUserInfo(config, provision)({ idToken: await idToken(staffClaims) }),
      "springboard_no_organization"
    );
  });
});
