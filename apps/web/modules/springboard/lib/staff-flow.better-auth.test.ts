import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, test, vi } from "vitest";
import { withSpringboardDatabaseHooks } from "./auth-hooks";
import type { TSpringboardStaffConfig } from "./config";
import { clearOidcProviderCache } from "./oidc";
import { getSpringboardGenericOAuthConfig } from "./staff-provider";
import { provisionSpringboardStaffUser } from "./staff-provisioning";

/**
 * The staff flow against a REAL Better Auth instance (memory adapter), with only Hydra's HTTP endpoints
 * stubbed: sign-in → authorization URL → callback → session. Proves what the unit tests can only
 * assume — that a policy refusal from `getUserInfo` becomes a redirect to the login page, that an
 * account linked by our provisioning is what Better Auth signs in, and that Better Auth never creates a
 * Springboard user itself (upstream's create hook is never reached).
 */

const BASE = "https://forms.springboard.test";
const ISSUER = "https://auth.springboard.test";

vi.mock("@/lib/constants", () => ({ WEBAPP_URL: "https://forms.springboard.test" }));
vi.mock("@formbricks/logger", () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock("./runtime-config", () => ({ getSpringboardStaffConfig: vi.fn(() => null) }));
vi.mock("./staff-provisioning", () => ({ provisionSpringboardStaffUser: vi.fn() }));

const config: TSpringboardStaffConfig = {
  issuer: ISSUER,
  clientId: "staff-client",
  clientSecret: "staff-secret",
  allowedDomains: ["springboard.vn"],
  defaultRole: "member",
  staffAccountTypes: ["employee"],
};

let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;
let issuedIdToken: (nonce: string) => Promise<string>;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
});

type TDb = Record<"user" | "session" | "account" | "verification", Record<string, unknown>[]>;

const stubHydra = () =>
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth2/auth`,
        token_endpoint: `${ISSUER}/oauth2/token`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }
    if (url === `${ISSUER}/.well-known/jwks.json`) return Response.json({ keys: [publicJwk] });
    if (url === `${ISSUER}/oauth2/token`) {
      return Response.json({
        access_token: "at",
        token_type: "bearer",
        expires_in: 3600,
        id_token: await issuedIdToken(currentNonce),
      });
    }
    return new Response("not found", { status: 404 });
  });

let currentNonce = "";
const upstreamCreateHook = vi.fn();

const createAuth = (db: TDb) =>
  betterAuth({
    baseURL: BASE,
    secret: "springboard-staff-flow-test-secret-32chars",
    database: memoryAdapter(db),
    account: { accountLinking: { enabled: false, allowDifferentEmails: false } },
    databaseHooks: withSpringboardDatabaseHooks({ user: { create: { before: upstreamCreateHook } } }),
    plugins: [genericOAuth({ config: getSpringboardGenericOAuthConfig(config) })],
  });

const runSignIn = async (auth: ReturnType<typeof createAuth>) => {
  const signIn = await auth.handler(
    new Request(`${BASE}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ provider: "springboard", callbackURL: "/", errorCallbackURL: "/auth/login" }),
    })
  );
  expect(signIn.status).toBe(200);
  const authorizationUrl = new URL(((await signIn.json()) as { url: string }).url);
  expect(authorizationUrl.searchParams.get("redirect_uri")).toBe(
    `${BASE}/api/auth/oauth2/callback/springboard`
  );
  expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
  currentNonce = authorizationUrl.searchParams.get("nonce") ?? "";
  const state = authorizationUrl.searchParams.get("state") ?? "";
  const cookie = signIn.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");

  // What legacy-sso-callback.ts maps /api/auth/oauth2/callback/springboard onto.
  return auth.handler(
    new Request(`${BASE}/api/auth/callback/springboard?code=c1&state=${state}`, { headers: { cookie } })
  );
};

const signToken = (claims: Record<string, unknown>) => (nonce: string) =>
  new SignJWT({ nonce, ...claims })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(ISSUER)
    .setAudience("staff-client")
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

const now = new Date();
const seedUser = (db: TDb) =>
  db.user.push({
    id: "u1",
    email: "linh@springboard.vn",
    name: "Linh",
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
  });

describe("staff sign-in through a real Better Auth instance", () => {
  let db: TDb;

  beforeEach(() => {
    db = { user: [], session: [], account: [], verification: [] };
    clearOidcProviderCache();
    stubHydra();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("an existing user is linked by our provisioning and signed in; Better Auth creates nobody", async () => {
    seedUser(db);
    issuedIdToken = signToken(staffClaims);
    vi.mocked(provisionSpringboardStaffUser).mockImplementation(async (identity) => {
      db.account.push({
        id: "a1",
        userId: "u1",
        providerId: "springboard",
        accountId: identity.sub,
        issuer: ISSUER,
        createdAt: now,
        updatedAt: now,
      });
      return { ok: true, value: { userId: "u1", created: false, linked: true } };
    });

    const response = await runSignIn(createAuth(db));

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/");
    expect(response.headers.getSetCookie().some((cookie) => cookie.includes("session_token="))).toBe(true);
    expect(db.session).toHaveLength(1);
    expect(db.session[0].userId).toBe("u1");
    expect(db.user).toHaveLength(1);
    expect(upstreamCreateHook).not.toHaveBeenCalled();
  });

  test("today's sub-only id_token is refused to the login page, with no user and no session", async () => {
    issuedIdToken = signToken({});

    const response = await runSignIn(createAuth(db));

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(`${BASE}/auth/login?error=springboard_missing_email`);
    expect(provisionSpringboardStaffUser).not.toHaveBeenCalled();
    expect(db.user).toHaveLength(0);
    expect(db.session).toHaveLength(0);
  });

  test("a non-staff account type is refused before provisioning", async () => {
    issuedIdToken = signToken({ ...staffClaims, account_type: "student" });

    const response = await runSignIn(createAuth(db));

    expect(response.headers.get("location")).toBe(`${BASE}/auth/login?error=springboard_not_staff`);
    expect(db.session).toHaveLength(0);
  });

  test("an existing user Better Auth would otherwise auto-link is NOT signed in without our link", async () => {
    // Global accountLinking stays off: if provisioning ever let a request through without writing the
    // link, Better Auth must refuse rather than link on its own.
    seedUser(db);
    issuedIdToken = signToken(staffClaims);
    vi.mocked(provisionSpringboardStaffUser).mockResolvedValue({
      ok: true,
      value: { userId: "u1", created: false, linked: true },
    });

    const response = await runSignIn(createAuth(db));

    expect(response.headers.get("location")).toContain("error=");
    expect(db.session).toHaveLength(0);
    expect(db.account).toHaveLength(0);
  });
});
