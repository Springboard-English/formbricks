import { describe, expect, test } from "vitest";
import {
  hasVerifiedRespondentEmail,
  isIdentifyingContextKey,
  isSpringboardSignInRequired,
  recordsSpringboardIdentity,
  setSpringboardSignInRequired,
} from "./respondent-survey";

const passField = { field: { source: "ingested" }, link: { storageKey: "sb_pass" } };

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

  test("identity is recorded through sign-in or a declared pass field, never on an anonymized survey", () => {
    expect(recordsSpringboardIdentity({ type: "app", metadata: {}, embeddedFields: [passField] })).toBe(true);
    expect(
      recordsSpringboardIdentity({
        type: "app",
        metadata: {},
        embeddedFields: [{ field: { source: "computed" }, link: { storageKey: "sb_pass" } }],
      })
    ).toBe(false);
    expect(
      recordsSpringboardIdentity({
        type: "link",
        metadata: { springboardSignInRequired: true },
        isAnonymizeResponsesEnabled: true,
      })
    ).toBe(false);
    expect(recordsSpringboardIdentity({ type: "app", metadata: {} })).toBe(false);
  });

  test.each([
    ["run_key", true],
    ["test_key", true],
    ["live_session_id", true],
    ["accountKey", true],
    ["email", true],
    ["Email", true],
    ["role", false],
    ["score_band", false],
    ["keyboard", false],
    ["moteg0j6a8nvc5y4e4xck9po", false],
  ])("context key %s identifies a person: %s", (key, expected) => {
    expect(isIdentifyingContextKey(key)).toBe(expected);
  });
});
