import { beforeEach, describe, expect, test, vi } from "vitest";
import { TooManyRequestsError } from "@formbricks/types/errors";
import { applyIPRateLimit } from "@/modules/core/rate-limit/helpers";
import { listActiveUserEmails, offboardSpringboardUser } from "@/modules/springboard/lib/offboard";
import { getSpringboardOffboardSecret } from "@/modules/springboard/lib/runtime-config";
import { handleListUsers, handleOffboard } from "./offboard-handlers";

// vitestSetup.ts stubs `createHash` to a constant; the secret comparison needs the real one.
vi.unmock("crypto");
vi.mock("@formbricks/logger", () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock("@/modules/core/rate-limit/helpers", () => ({ applyIPRateLimit: vi.fn() }));
vi.mock("@/modules/springboard/lib/runtime-config", () => ({ getSpringboardOffboardSecret: vi.fn() }));
vi.mock("@/modules/springboard/lib/offboard", async (importOriginal) => ({
  isAuthorizedSpringboardRequest: (
    await importOriginal<typeof import("@/modules/springboard/lib/offboard")>()
  ).isAuthorizedSpringboardRequest,
  offboardSpringboardUser: vi.fn(),
  listActiveUserEmails: vi.fn(),
}));

const SECRET = "s".repeat(40);

const post = (body: unknown, authorization: string | null = `Bearer ${SECRET}`) =>
  new Request("https://forms.springboard.vn/api/springboard/offboard", {
    method: "POST",
    headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getSpringboardOffboardSecret).mockReturnValue(SECRET);
  vi.mocked(applyIPRateLimit).mockResolvedValue({ allowed: true });
  vi.mocked(offboardSpringboardUser).mockResolvedValue({ status: "ok" });
});

describe("POST /api/springboard/offboard", () => {
  test("404 while the secret is unset", async () => {
    vi.mocked(getSpringboardOffboardSecret).mockReturnValue(null);
    expect((await handleOffboard(post({ email: "a@springboard.vn" }))).status).toBe(404);
    expect(offboardSpringboardUser).not.toHaveBeenCalled();
  });

  test("401 without the right secret", async () => {
    expect((await handleOffboard(post({ email: "a@springboard.vn" }, null))).status).toBe(401);
    expect((await handleOffboard(post({ email: "a@springboard.vn" }, "Bearer wrong"))).status).toBe(401);
    expect(offboardSpringboardUser).not.toHaveBeenCalled();
  });

  test("429 when rate-limited, checked before the secret", async () => {
    vi.mocked(applyIPRateLimit).mockRejectedValue(new TooManyRequestsError("slow down"));
    expect((await handleOffboard(post({ email: "a@springboard.vn" }, "Bearer wrong"))).status).toBe(429);
  });

  test("400 on a malformed body", async () => {
    expect((await handleOffboard(post("{not json"))).status).toBe(400);
    expect((await handleOffboard(post({ email: "not-an-email" }))).status).toBe(400);
  });

  test("200 with the same body for a known and an unknown address", async () => {
    const known = await handleOffboard(post({ email: "a@springboard.vn" }));
    const unknown = await handleOffboard(post({ email: "nobody@springboard.vn" }));
    expect(known.status).toBe(200);
    expect(unknown.status).toBe(200);
    expect(await known.json()).toEqual(await unknown.json());
    expect(offboardSpringboardUser).toHaveBeenCalledWith("a@springboard.vn");
  });

  test("409 for the last active owner", async () => {
    vi.mocked(offboardSpringboardUser).mockResolvedValue({ status: "last_owner" });
    const response = await handleOffboard(post({ email: "owner@springboard.vn" }));
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: "last_owner" });
  });
});

describe("GET /api/springboard/users", () => {
  const get = (authorization: string | null = `Bearer ${SECRET}`) =>
    new Request("https://forms.springboard.vn/api/springboard/users", {
      headers: authorization ? { authorization } : {},
    });

  test("lists active emails behind the same secret", async () => {
    vi.mocked(listActiveUserEmails).mockResolvedValue(["a@springboard.vn"]);
    const response = await handleListUsers(get());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ emails: ["a@springboard.vn"] });
  });

  test("401 without the secret", async () => {
    expect((await handleListUsers(get(null))).status).toBe(401);
    expect(listActiveUserEmails).not.toHaveBeenCalled();
  });
});
