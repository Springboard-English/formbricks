import { describe, expect, test } from "vitest";
import {
  hasVerifiedRespondentEmail,
  isSpringboardSignInRequired,
  setSpringboardSignInRequired,
} from "./respondent-survey";

describe("per-survey Springboard sign-in setting", () => {
  test("is stored in metadata without disturbing the link-preview keys", () => {
    const survey = { type: "link", metadata: { title: { default: "Hi" } } };
    const on = setSpringboardSignInRequired(survey, true);
    expect(on.metadata).toEqual({ title: { default: "Hi" }, springboardSignInRequired: true });
    expect(isSpringboardSignInRequired(on)).toBe(true);

    const off = setSpringboardSignInRequired(on, false);
    expect(off.metadata).toEqual({ title: { default: "Hi" } });
    expect(isSpringboardSignInRequired(off)).toBe(false);
  });

  test("applies to link surveys only and only to a literal true", () => {
    expect(isSpringboardSignInRequired({ type: "app", metadata: { springboardSignInRequired: true } })).toBe(
      false
    );
    expect(
      isSpringboardSignInRequired({ type: "link", metadata: { springboardSignInRequired: "true" } })
    ).toBe(false);
    expect(isSpringboardSignInRequired({ type: "link", metadata: null })).toBe(false);
  });

  test("verified-email display covers both core email verification and Springboard sign-in", () => {
    expect(hasVerifiedRespondentEmail({ type: "link", isVerifyEmailEnabled: true, metadata: {} })).toBe(true);
    expect(
      hasVerifiedRespondentEmail({
        type: "link",
        isVerifyEmailEnabled: false,
        metadata: { springboardSignInRequired: true },
      })
    ).toBe(true);
    expect(hasVerifiedRespondentEmail({ type: "link", isVerifyEmailEnabled: false, metadata: {} })).toBe(
      false
    );
  });
});
