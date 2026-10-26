import { beforeEach, describe, expect, test, vi } from "vitest";
import { getRespondentCookieName, signRespondentCookie } from "./respondent-cookie";
import {
  enforceSpringboardRespondentGate,
  enforceSpringboardRespondentGateOnUpdate,
} from "./respondent-gate";
import { getSpringboardRespondentConfig } from "./runtime-config";

vi.mock("./runtime-config", () => ({ getSpringboardRespondentConfig: vi.fn() }));

const SECRET = "c".repeat(32);
const survey = { id: "survey1", type: "link", metadata: { springboardSignInRequired: true } };
const identity = { email: "student@gmail.com", sub: "sb-42", accountType: "student" };
const cookieFor = (surveyId: string, value = signRespondentCookie(identity, surveyId, SECRET)) =>
  `other=1; ${getRespondentCookieName(surveyId)}=${value}`;

beforeEach(() => {
  vi.mocked(getSpringboardRespondentConfig).mockReturnValue({
    issuer: "https://auth.springboard.vn",
    clientId: "respondent-client",
    clientSecret: "x",
    cookieSecret: SECRET,
  });
});

describe("response create gate", () => {
  test("surveys without the setting are untouched, whatever the body says", () => {
    const data = { q1: "yes", springboardAccountKey: "mine" };
    expect(
      enforceSpringboardRespondentGate({
        survey: { ...survey, metadata: {} },
        responseData: data,
        cookieHeader: null,
      })
    ).toBeNull();
    expect(data).toEqual({ q1: "yes", springboardAccountKey: "mine" });
  });

  test("stamps the cookie's identity, overwriting spoofed values in the body", () => {
    const data = {
      q1: "yes",
      verifiedEmail: "ceo@springboard.vn",
      springboardAccountKey: "sb-ceo",
      springboardAccountType: "employee",
    };
    expect(
      enforceSpringboardRespondentGate({ survey, responseData: data, cookieHeader: cookieFor("survey1") })
    ).toBeNull();
    expect(data).toEqual({
      q1: "yes",
      verifiedEmail: "student@gmail.com",
      springboardAccountKey: "sb-42",
      springboardAccountType: "student",
    });
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
      verifiedEmail: "ceo@springboard.vn",
      springboardAccountKey: "sb-ceo",
    };
    const response = enforceSpringboardRespondentGate({ survey, responseData: data, cookieHeader });
    expect(response?.status).toBe(403);
    expect(data).toEqual({});
  });

  test("fails closed when the instance has no respondent client configured", () => {
    vi.mocked(getSpringboardRespondentConfig).mockReturnValue(null);
    const response = enforceSpringboardRespondentGate({
      survey,
      responseData: {},
      cookieHeader: cookieFor("survey1"),
    });
    expect(response?.status).toBe(403);
  });
});

describe("response update gate (partial responses)", () => {
  const existing = { q1: "yes", verifiedEmail: "student@gmail.com", springboardAccountKey: "sb-42" };

  test("the same signed-in respondent may continue; identity keys in the update are dropped", () => {
    const update: Record<string, string> = {
      q2: "no",
      verifiedEmail: "x@y.z",
      springboardAccountKey: "sb-ceo",
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
});
