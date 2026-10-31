import { type CryptoKey, SignJWT, exportSPKI, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, test, vi } from "vitest";
import { getRespondentCookieName, signRespondentCookie } from "./respondent-cookie";
import {
  enforceSpringboardRespondentGate,
  enforceSpringboardRespondentGateOnUpdate,
} from "./respondent-gate";
import { getSpringboardPassConfig, getSpringboardRespondentConfig } from "./runtime-config";

vi.mock("./runtime-config", () => ({
  getSpringboardRespondentConfig: vi.fn(),
  getSpringboardPassConfig: vi.fn(),
}));

const SECRET = "c".repeat(32);
const ISSUER = "https://api.springboard.vn";
const AUDIENCE = "https://forms.springboard.vn";
const survey = { id: "survey1", type: "link", metadata: { springboardSignInRequired: true } };
const appSurvey = { id: "survey2", type: "app", metadata: {} };
const identity = { email: "student@gmail.com", emailVerified: false, sub: "sb-42", accountType: "student" };
const cookieFor = (surveyId: string, value = signRespondentCookie(identity, surveyId, SECRET)) =>
  `other=1; ${getRespondentCookieName(surveyId)}=${value}`;

let privateKey: CryptoKey;
let publicKeyPem: string;

const pass = ({ iss = ISSUER, aud = AUDIENCE, ...claims }: Record<string, unknown> = {}, life = 600) => {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    typ: "respondent_pass",
    email: "staff@springboard.vn",
    email_verified: true,
    account_type: "employee",
    ...claims,
  })
    .setProtectedHeader({ alg: "RS256" })
    .setSubject("sb-7")
    .setIssuer(String(iss))
    .setAudience(String(aud))
    .setIssuedAt(now)
    .setExpirationTime(now + life)
    .sign(privateKey);
};

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  privateKey = pair.privateKey;
  publicKeyPem = await exportSPKI(pair.publicKey);
});

beforeEach(() => {
  vi.mocked(getSpringboardRespondentConfig).mockReturnValue({
    issuer: "https://auth.springboard.vn",
    clientId: "respondent-client",
    clientSecret: "x",
    cookieSecret: SECRET,
  });
  vi.mocked(getSpringboardPassConfig).mockReturnValue({ publicKeyPem, issuer: ISSUER, audience: AUDIENCE });
});

// A client-sent `verifiedEmail` never reaches the gate: the ingest contract drops it first (it is a
// forbidden field name), and a value present here was written by core's own email-verification gate.
describe("response create gate: sign-in cookie", () => {
  test("a survey without the setting keeps its answers, but never a client-written identity", async () => {
    const data = { q1: "yes", springboardAccountKey: "mine", springboardEmail: "ceo@springboard.vn" };
    expect(
      await enforceSpringboardRespondentGate({
        survey: { ...survey, metadata: {} },
        responseData: data,
        cookieHeader: null,
      })
    ).toBeNull();
    expect(data).toEqual({ q1: "yes" });
  });

  test("stamps the cookie's account, keeping an unverified address out of verifiedEmail", async () => {
    const data = {
      q1: "yes",
      springboardEmail: "ceo@springboard.vn",
      springboardAccountKey: "sb-ceo",
      springboardAccountType: "employee",
    };
    expect(
      await enforceSpringboardRespondentGate({
        survey,
        responseData: data,
        cookieHeader: cookieFor("survey1"),
      })
    ).toBeNull();
    expect(data).toEqual({
      q1: "yes",
      springboardEmail: "student@gmail.com",
      springboardAccountKey: "sb-42",
      springboardAccountType: "student",
    });
  });

  test("a verified address also lands in core's verifiedEmail", async () => {
    const staff = { ...identity, email: "a@springboard.vn", emailVerified: true, accountType: "employee" };
    const data: Record<string, string> = {};
    await enforceSpringboardRespondentGate({
      survey,
      responseData: data,
      cookieHeader: cookieFor("survey1", signRespondentCookie(staff, "survey1", SECRET)),
    });
    expect(data.verifiedEmail).toBe("a@springboard.vn");
  });

  test.each([
    ["a missing cookie", null],
    ["a cookie for another survey", cookieFor("survey2").replace("survey2=", "survey1=")],
    ["another survey's cookie under its own name", cookieFor("survey2")],
    ["a tampered cookie", cookieFor("survey1", `${signRespondentCookie(identity, "survey1", SECRET)}x`)],
    [
      "a cookie signed with another key",
      cookieFor("survey1", signRespondentCookie(identity, "survey1", "z".repeat(32))),
    ],
    [
      "an expired cookie",
      cookieFor(
        "survey1",
        signRespondentCookie(identity, "survey1", SECRET, Date.now() - 3 * 60 * 60 * 1000)
      ),
    ],
  ])("403 with %s, and spoofed values never survive", async (_label, cookieHeader) => {
    const data: Record<string, string> = {
      springboardEmail: "ceo@springboard.vn",
      springboardAccountKey: "sb-ceo",
    };
    const response = await enforceSpringboardRespondentGate({ survey, responseData: data, cookieHeader });
    expect(response?.status).toBe(403);
    expect(data).toEqual({});
  });

  test("fails closed when the instance has no respondent client configured", async () => {
    vi.mocked(getSpringboardRespondentConfig).mockReturnValue(null);
    const response = await enforceSpringboardRespondentGate({
      survey,
      responseData: {},
      cookieHeader: cookieFor("survey1"),
    });
    expect(response?.status).toBe(403);
  });
});

describe("response create gate: respondent pass", () => {
  test("a valid pass identifies an in-app answer, and the pass itself is never stored", async () => {
    const data: Record<string, string> = { q1: "5", sb_pass: await pass() };
    expect(
      await enforceSpringboardRespondentGate({ survey: appSurvey, responseData: data, cookieHeader: null })
    ).toBeNull();
    expect(data).toEqual({
      q1: "5",
      verifiedEmail: "staff@springboard.vn",
      springboardEmail: "staff@springboard.vn",
      springboardAccountKey: "sb-7",
      springboardAccountType: "employee",
    });
  });

  test("a pass plus a spoofed identity: the pass wins", async () => {
    const data: Record<string, string> = { sb_pass: await pass(), springboardAccountKey: "sb-ceo" };
    await enforceSpringboardRespondentGate({ survey: appSurvey, responseData: data, cookieHeader: null });
    expect(data.springboardAccountKey).toBe("sb-7");
  });

  test.each([
    ["expired", () => pass({}, -60)],
    ["for another audience", () => pass({ aud: "https://elsewhere.example" })],
    ["from another issuer", () => pass({ iss: "https://evil.example" })],
    ["of another type", () => pass({ typ: "access_token" })],
    ["living longer than ten minutes", () => pass({}, 3600)],
    ["tampered", async () => `${await pass()}x`],
  ])("a pass %s saves the answer without identity", async (_label, make) => {
    const data: Record<string, string> = { q1: "5", sb_pass: await make(), springboardAccountKey: "sb-ceo" };
    expect(
      await enforceSpringboardRespondentGate({ survey: appSurvey, responseData: data, cookieHeader: null })
    ).toBeNull();
    expect(data).toEqual({ q1: "5" });
  });

  test("passes are ignored while the instance has no pass key configured", async () => {
    vi.mocked(getSpringboardPassConfig).mockReturnValue(null);
    const data: Record<string, string> = { sb_pass: await pass() };
    await enforceSpringboardRespondentGate({ survey: appSurvey, responseData: data, cookieHeader: null });
    expect(data).toEqual({});
  });
});

describe("response create gate: anonymized surveys", () => {
  const anonymous = { ...appSurvey, isAnonymizeResponsesEnabled: true };

  test("no identity, no identifying context, and the URL cut to its origin", async () => {
    const data: Record<string, string> = {
      q1: "5",
      sb_pass: await pass(),
      run_key: "r-1",
      test_key: "t-1",
      email: "x@y.z",
      role: "student",
      score_band: "low",
    };
    const meta = { url: "https://leap.springboard.vn/teacher/tests/t-1/results?run=r-1" };
    expect(
      await enforceSpringboardRespondentGate({
        survey: anonymous,
        responseData: data,
        cookieHeader: null,
        meta,
      })
    ).toBeNull();
    expect(data).toEqual({ q1: "5", role: "student", score_band: "low" });
    expect(meta.url).toBe("https://leap.springboard.vn");
  });

  test("with sign-in also required, the cookie only decides who may answer", async () => {
    const data: Record<string, string> = { q1: "yes" };
    const both = { ...survey, isAnonymizeResponsesEnabled: true };
    expect(
      await enforceSpringboardRespondentGate({ survey: both, responseData: data, cookieHeader: null })
    ).not.toBeNull();
    expect(
      await enforceSpringboardRespondentGate({
        survey: both,
        responseData: data,
        cookieHeader: cookieFor("survey1"),
      })
    ).toBeNull();
    expect(data).toEqual({ q1: "yes" });
  });
});

describe("response update gate (partial responses)", () => {
  const existing = { q1: "yes", springboardEmail: "student@gmail.com", springboardAccountKey: "sb-42" };

  test("the same signed-in respondent may continue; identity keys in the update are dropped", () => {
    const update: Record<string, string> = {
      q2: "no",
      springboardEmail: "x@y.z",
      springboardAccountKey: "sb-ceo",
      sb_pass: "anything",
    };
    expect(
      enforceSpringboardRespondentGateOnUpdate({
        survey,
        existingResponseData: existing,
        updateData: update,
        cookieHeader: cookieFor("survey1"),
      })
    ).toBeNull();
    expect(update).toEqual({ q2: "no" });
  });

  test("another signed-in respondent cannot finish someone else's response", () => {
    const otherCookie = cookieFor(
      "survey1",
      signRespondentCookie({ ...identity, sub: "sb-99" }, "survey1", SECRET)
    );
    expect(
      enforceSpringboardRespondentGateOnUpdate({
        survey,
        existingResponseData: existing,
        updateData: { q2: "no" },
        cookieHeader: otherCookie,
      })?.status
    ).toBe(403);
  });

  test("no cookie, no update", () => {
    expect(
      enforceSpringboardRespondentGateOnUpdate({
        survey,
        existingResponseData: existing,
        updateData: { q2: "no" },
        cookieHeader: null,
      })?.status
    ).toBe(403);
  });

  test("an anonymized survey's update drops identifying context too", () => {
    const update: Record<string, string> = { q2: "no", run_key: "r-1" };
    enforceSpringboardRespondentGateOnUpdate({
      survey: { ...appSurvey, isAnonymizeResponsesEnabled: true },
      existingResponseData: {},
      updateData: update,
      cookieHeader: null,
    });
    expect(update).toEqual({ q2: "no" });
  });
});
