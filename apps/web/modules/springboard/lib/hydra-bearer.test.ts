import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, test, vi } from "vitest";
import { type THydraBearerDeps, resolveHydraBearer } from "./hydra-bearer";
import { HYDRA_BEARER_SCOPES, readTokenScopes, requiredHydraBearerScope } from "./hydra-bearer-policy";

vi.mock("@formbricks/database", () => ({ prisma: { account: { findFirst: vi.fn() } } }));
vi.mock("@formbricks/logger", () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock("@/modules/api/lib/api-key-auth", () => ({ getBearerTokenFromHeaders: vi.fn() }));
vi.mock("./runtime-config", () => ({ getSpringboardHydraBearerConfig: vi.fn(() => null) }));

const ISSUER = "https://auth.springboard.vn";
const AUDIENCE = "https://forms.springboard.vn";
const CONFIG = { issuer: ISSUER, audience: AUDIENCE };
const SUB = "019d0c0b-aaaa-bbbb-cccc-000000000001";
const LINKED = { id: "user-1", email: "staff@springboard.vn", isActive: true };

let jwks: ReturnType<typeof createLocalJWKSet>;
let privateKey: CryptoKey;
let otherPrivateKey: CryptoKey;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  const other = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  otherPrivateKey = other.privateKey;
  jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256" }] });
});

type TSignOptions = {
  scp?: string[];
  issuer?: string;
  audience?: string | string[];
  key?: CryptoKey;
  exp?: string | number;
};

const sign = ({
  scp = [HYDRA_BEARER_SCOPES.surveysRead],
  issuer = ISSUER,
  audience = [AUDIENCE, `${ISSUER}/oauth2/token`],
  key = privateKey,
  exp = "15m",
}: TSignOptions = {}) =>
  new SignJWT({ scp, client_id: "springboard-api-formbricks", ext: {} })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(SUB)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(key);

const findLinkedUser = vi.fn<THydraBearerDeps["findLinkedUser"]>();
const deps = (): THydraBearerDeps => ({ getJwks: async () => jwks, findLinkedUser });
const resolve = (token: string | null, method = "GET", pathname = "/api/v3/surveys") =>
  resolveHydraBearer({ token, method, pathname }, CONFIG, deps());

beforeEach(() => {
  findLinkedUser.mockReset();
  findLinkedUser.mockResolvedValue(LINKED);
});

describe("requiredHydraBearerScope", () => {
  test.each([
    ["GET", "/api/v3/surveys", HYDRA_BEARER_SCOPES.surveysRead],
    ["GET", "/api/v3/surveys/abc/", HYDRA_BEARER_SCOPES.surveysRead],
    ["POST", "/api/v3/surveys", HYDRA_BEARER_SCOPES.surveysWrite],
    ["PATCH", "/api/v3/surveys/abc", HYDRA_BEARER_SCOPES.surveysWrite],
    ["POST", "/api/v3/surveys/validate", HYDRA_BEARER_SCOPES.surveysWrite],
    ["GET", "/api/v3/responses", HYDRA_BEARER_SCOPES.responsesRead],
    ["GET", "/api/v3/responses/count", HYDRA_BEARER_SCOPES.responsesRead],
  ])("%s %s needs %s", (method, path, scope) => {
    expect(requiredHydraBearerScope(method, path)).toBe(scope);
  });

  test.each([
    ["POST", "/api/v3/responses"],
    ["DELETE", "/api/v3/responses/abc"],
    ["GET", "/api/v3/tags"],
    ["GET", "/api/v3/surveysx"],
    ["GET", "/api/v3/workflows"],
  ])("%s %s is closed to Hydra tokens", (method, path) => {
    expect(requiredHydraBearerScope(method, path)).toBeNull();
  });
});

describe("readTokenScopes", () => {
  test("reads Hydra's scp array and an RFC 9068 scope string", () => {
    expect(readTokenScopes({ scp: ["surveys:read", 7] })).toEqual(["surveys:read"]);
    expect(readTokenScopes({ scope: "surveys:read  surveys:write" })).toEqual([
      "surveys:read",
      "surveys:write",
    ]);
    expect(readTokenScopes({})).toEqual([]);
  });
});

describe("resolveHydraBearer", () => {
  test("a good token becomes a session for the linked user", async () => {
    const result = await resolve(await sign());
    expect(result.kind).toBe("session");
    if (result.kind !== "session") return;
    expect(result.session.user).toEqual({ id: "user-1", email: "staff@springboard.vn", isActive: true });
    expect(Date.parse(result.session.expires)).toBeGreaterThan(Date.now());
    expect(findLinkedUser).toHaveBeenCalledWith(SUB);
  });

  test("no bearer, an API key, a non-JWT or another issuer's token is not ours", async () => {
    expect(await resolve(null)).toEqual({ kind: "absent" });
    expect(await resolve("fbk_abc")).toEqual({ kind: "absent" });
    expect(await resolve("opaque-token")).toEqual({ kind: "absent" });
    expect(await resolve(await sign({ issuer: "https://elsewhere.example" }))).toEqual({ kind: "absent" });
  });

  test("everything is ignored while the feature is off", async () => {
    const result = await resolveHydraBearer(
      { token: await sign(), method: "GET", pathname: "/api/v3/surveys" },
      null,
      deps()
    );
    expect(result).toEqual({ kind: "absent" });
  });

  test.each<[string, () => Promise<string>]>([
    ["a bad signature", () => sign({ key: otherPrivateKey })],
    ["another audience", () => sign({ audience: "https://api.springboard.vn" })],
    ["an expired token", () => sign({ exp: Math.floor(Date.now() / 1000) - 60 })],
  ])("%s is refused", async (_label, make) => {
    expect((await resolve(await make())).kind).toBe("refused");
    expect(findLinkedUser).not.toHaveBeenCalled();
  });

  test("a token without the route's scope is refused", async () => {
    const readOnly = await sign({ scp: [HYDRA_BEARER_SCOPES.surveysRead] });
    expect(await resolve(readOnly, "PATCH", "/api/v3/surveys/abc")).toEqual({
      kind: "refused",
      reason: "token lacks surveys:write",
    });
    expect((await resolve(readOnly, "GET", "/api/v3/responses")).kind).toBe("refused");
  });

  test("a route closed to Hydra tokens is refused even with every scope", async () => {
    const all = await sign({ scp: Object.values(HYDRA_BEARER_SCOPES) });
    expect((await resolve(all, "GET", "/api/v3/tags")).kind).toBe("refused");
  });

  test("an unlinked or inactive account is refused", async () => {
    const token = await sign();
    findLinkedUser.mockResolvedValueOnce(null);
    expect((await resolve(token)).kind).toBe("refused");
    findLinkedUser.mockResolvedValueOnce({ ...LINKED, isActive: false });
    expect((await resolve(token)).kind).toBe("refused");
  });

  test("a JWKS that cannot be fetched refuses rather than throws", async () => {
    const result = await resolveHydraBearer(
      { token: await sign(), method: "GET", pathname: "/api/v3/surveys" },
      CONFIG,
      {
        getJwks: async () => {
          throw new Error("discovery down");
        },
        findLinkedUser,
      }
    );
    expect(result.kind).toBe("refused");
  });
});
