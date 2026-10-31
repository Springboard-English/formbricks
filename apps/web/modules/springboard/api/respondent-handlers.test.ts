import { beforeEach, describe, expect, test, vi } from "vitest";
import { getSurvey } from "@/lib/survey/service";
import { getOidcProvider } from "@/modules/springboard/lib/oidc";
import {
  RESPONDENT_FLOW_COOKIE_NAME,
  signRespondentFlowCookie,
  verifyRespondentCookie,
} from "@/modules/springboard/lib/respondent-cookie";
import { completeRespondentCallback } from "@/modules/springboard/lib/respondent-flow";
import { getSpringboardRespondentConfig } from "@/modules/springboard/lib/runtime-config";
import { handleRespondentCallback, handleRespondentStart } from "./respondent-handlers";

vi.mock("@formbricks/logger", () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));
vi.mock("@/lib/getPublicUrl", () => ({ getPublicDomain: () => "https://forms.springboard.vn" }));
vi.mock("@/lib/survey/service", () => ({ getSurvey: vi.fn() }));
vi.mock("@/modules/auth/lib/auth-cookies", () => ({ USE_SECURE_COOKIES: true }));
vi.mock("@/modules/core/rate-limit/helpers", () => ({ applyIPRateLimit: vi.fn() }));
vi.mock("@/modules/springboard/lib/runtime-config", () => ({ getSpringboardRespondentConfig: vi.fn() }));
vi.mock("@/modules/springboard/lib/oidc", () => ({ getOidcProvider: vi.fn() }));
vi.mock("@/modules/springboard/lib/respondent-flow", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/modules/springboard/lib/respondent-flow")>()),
  completeRespondentCallback: vi.fn(),
}));
// The respondent flow must never reach Better Auth: importing it at all would fail this suite.
vi.mock("@/modules/auth/lib/auth", () => {
  throw new Error("respondent flow imported Better Auth");
});

const SECRET = "c".repeat(32);
const ISSUER = "https://auth.springboard.vn";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getSpringboardRespondentConfig).mockReturnValue({
    issuer: ISSUER,
    clientId: "respondent-client",
    clientSecret: "x",
    cookieSecret: SECRET,
  });
  vi.mocked(getOidcProvider).mockResolvedValue({
    metadata: {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/oauth2/auth`,
      token_endpoint: `${ISSUER}/oauth2/token`,
      jwks_uri: `${ISSUER}/jwks`,
    },
    jwks: vi.fn() as never,
  });
});

describe("respondent start", () => {
  test("redirects to Hydra and sets a short-lived HttpOnly flow cookie", async () => {
    vi.mocked(getSurvey).mockResolvedValue({
      id: "survey1",
      type: "link",
      metadata: { springboardSignInRequired: true },
    } as never);

    const response = await handleRespondentStart(
      new Request(
        "https://forms.springboard.vn/api/springboard/respondent/start?surveyId=survey1&returnTo=%2Fs%2Fsurvey1%3FsuId%3Dabc"
      )
    );

    expect(response.status).toBe(303);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.searchParams.get("redirect_uri")).toBe(
      "https://forms.springboard.vn/api/springboard/respondent/callback"
    );
    const setCookie = response.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain(`${RESPONDENT_FLOW_COOKIE_NAME}=`);
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Secure/i);
    expect(setCookie).toMatch(/SameSite=lax/i);
  });

  test("404 for a survey that does not require Springboard sign-in", async () => {
    vi.mocked(getSurvey).mockResolvedValue({ id: "survey1", type: "link", metadata: {} } as never);
    const response = await handleRespondentStart(
      new Request("https://forms.springboard.vn/api/springboard/respondent/start?surveyId=survey1")
    );
    expect(response.status).toBe(404);
  });

  test("404 while the respondent client is not configured", async () => {
    vi.mocked(getSpringboardRespondentConfig).mockReturnValue(null);
    const response = await handleRespondentStart(
      new Request("https://forms.springboard.vn/api/springboard/respondent/start?surveyId=survey1")
    );
    expect(response.status).toBe(404);
  });
});

describe("respondent callback", () => {
  const flow = {
    surveyId: "survey1",
    state: "st",
    nonce: "n",
    codeVerifier: "v",
    returnTo: "/s/survey1?suId=abc&suToken=t",
  };
  const request = () =>
    new Request("https://forms.springboard.vn/api/springboard/respondent/callback?code=c&state=st", {
      headers: { cookie: `${RESPONDENT_FLOW_COOKIE_NAME}=${signRespondentFlowCookie(flow, SECRET)}` },
    });

  test("sets the survey-bound identity cookie and returns to the survey with its query string", async () => {
    vi.mocked(completeRespondentCallback).mockResolvedValue({
      ok: true,
      identity: { email: "student@gmail.com", emailVerified: false, sub: "sb-42", accountType: "student" },
    });

    const response = await handleRespondentCallback(request());

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "https://forms.springboard.vn/s/survey1?suId=abc&suToken=t"
    );
    const cookies = response.headers.getSetCookie();
    const identityCookie = cookies.find((cookie) => cookie.startsWith("sb_respondent_survey1="));
    expect(identityCookie).toMatch(/HttpOnly/i);
    expect(identityCookie).toMatch(/Max-Age=7200/);
    const value = identityCookie?.split(";")[0].split("=").slice(1).join("=");
    expect(verifyRespondentCookie(value, "survey1", SECRET)).toEqual({
      email: "student@gmail.com",
      emailVerified: false,
      sub: "sb-42",
      accountType: "student",
    });
    // The flow cookie is cleared, and no Better Auth session cookie is ever set.
    expect(cookies.some((cookie) => cookie.startsWith(`${RESPONDENT_FLOW_COOKIE_NAME}=;`))).toBe(true);
    expect(cookies.some((cookie) => cookie.includes("session_token"))).toBe(false);
  });

  test("a refused sign-in returns to the survey with the error and no identity cookie", async () => {
    vi.mocked(completeRespondentCallback).mockResolvedValue({ ok: false, error: "respondent_invalid_token" });

    const response = await handleRespondentCallback(request());

    expect(response.headers.get("location")).toContain("springboardError=respondent_invalid_token");
    expect(
      response.headers.getSetCookie().some((cookie) => cookie.startsWith("sb_respondent_survey1="))
    ).toBe(false);
  });

  test("400 without the flow cookie this browser started", async () => {
    const response = await handleRespondentCallback(
      new Request("https://forms.springboard.vn/api/springboard/respondent/callback?code=c&state=st")
    );
    expect(response.status).toBe(400);
    expect(completeRespondentCallback).not.toHaveBeenCalled();
  });
});
