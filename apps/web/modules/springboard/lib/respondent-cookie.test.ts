import { createHmac } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  RESPONDENT_COOKIE_MAX_AGE_SECONDS,
  readCookie,
  signRespondentCookie,
  signRespondentFlowCookie,
  verifyRespondentCookie,
  verifyRespondentFlowCookie,
} from "./respondent-cookie";

const SECRET = "k".repeat(32);
const identity = { email: "student@gmail.com", emailVerified: false, sub: "sb-42", accountType: "student" };
const NOW = Date.UTC(2026, 9, 26, 12);

describe("respondent cookie", () => {
  test("round-trips for the survey it was issued for", () => {
    const cookie = signRespondentCookie(identity, "survey1", SECRET, NOW);
    expect(verifyRespondentCookie(cookie, "survey1", SECRET, NOW)).toEqual(identity);
  });

  test("a cookie for another survey is refused", () => {
    const cookie = signRespondentCookie(identity, "survey1", SECRET, NOW);
    expect(verifyRespondentCookie(cookie, "survey2", SECRET, NOW)).toBeNull();
  });

  test("an expired cookie is refused (two hours)", () => {
    const cookie = signRespondentCookie(identity, "survey1", SECRET, NOW);
    const later = NOW + RESPONDENT_COOKIE_MAX_AGE_SECONDS * 1000 + 1000;
    expect(verifyRespondentCookie(cookie, "survey1", SECRET, later)).toBeNull();
  });

  test("a tampered payload is refused", () => {
    const [, signature] = signRespondentCookie(identity, "survey1", SECRET, NOW).split(".");
    const forged = Buffer.from(
      JSON.stringify({
        v: 1,
        purpose: "identity",
        sid: "survey1",
        exp: Math.floor(NOW / 1000) + 3600,
        data: { ...identity, email: "ceo@springboard.vn" },
      })
    ).toString("base64url");
    expect(verifyRespondentCookie(`${forged}.${signature}`, "survey1", SECRET, NOW)).toBeNull();
  });

  test("a tampered signature, another key, garbage and a missing cookie are refused", () => {
    const cookie = signRespondentCookie(identity, "survey1", SECRET, NOW);
    const flipped = `${cookie.slice(0, -2)}${cookie.endsWith("AA") ? "BB" : "AA"}`;
    expect(verifyRespondentCookie(flipped, "survey1", SECRET, NOW)).toBeNull();
    expect(verifyRespondentCookie(cookie, "survey1", "x".repeat(32), NOW)).toBeNull();
    expect(verifyRespondentCookie("not-a-cookie", "survey1", SECRET, NOW)).toBeNull();
    expect(verifyRespondentCookie(undefined, "survey1", SECRET, NOW)).toBeNull();
  });

  test("a flow cookie cannot stand in for an identity cookie", () => {
    const flow = signRespondentFlowCookie(
      { surveyId: "survey1", state: "s", nonce: "n", codeVerifier: "v", returnTo: "/s/survey1" },
      SECRET,
      NOW
    );
    expect(verifyRespondentCookie(flow, "survey1", SECRET, NOW)).toBeNull();
    expect(verifyRespondentFlowCookie(flow, SECRET, NOW)).toMatchObject({ state: "s" });
  });

  test("a cookie signed before emailVerified existed reads as verified, as it then always was", () => {
    const { emailVerified: _dropped, ...older } = identity;
    const body = Buffer.from(
      JSON.stringify({
        v: 1,
        purpose: "identity",
        sid: "survey1",
        exp: Math.floor(NOW / 1000) + 60,
        data: older,
      })
    ).toString("base64url");
    const signature = createHmac("sha256", SECRET).update(body).digest("base64url");
    expect(verifyRespondentCookie(`${body}.${signature}`, "survey1", SECRET, NOW)).toEqual({
      ...older,
      emailVerified: true,
    });
  });

  test("carries no token, only the identity fields", () => {
    const cookie = signRespondentCookie(
      { ...identity, idToken: "eyJ...", accessToken: "secret" } as typeof identity,
      "survey1",
      SECRET,
      NOW
    );
    const payload = JSON.parse(Buffer.from(cookie.split(".")[0], "base64url").toString());
    expect(Object.keys(payload.data).sort()).toEqual(["accountType", "email", "emailVerified", "sub"]);
  });

  test("readCookie finds one cookie in a header", () => {
    expect(readCookie("a=1; sb_respondent_x=abc.def; b=2", "sb_respondent_x")).toBe("abc.def");
    expect(readCookie("a=1", "sb_respondent_x")).toBeUndefined();
    expect(readCookie(null, "a")).toBeUndefined();
  });
});
