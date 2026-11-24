import { describe, expect, test } from "vitest";
import {
  hasVerifiedRespondentEmail,
  isIdentifyingContextKey,
  isRespondentAllowed,
  isSpringboardSignInRequired,
  isSpringboardStaffOnly,
  recordsSpringboardIdentity,
  setSpringboardSignInRequired,
  setSpringboardStaffOnly,
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

describe("per-survey staff-only setting", () => {
  const link = { type: "link", metadata: { springboardSignInRequired: true, linkPreview: "x" } };

  test("round-trips in metadata and means nothing without sign-in", () => {
    const on = setSpringboardStaffOnly(link, true);
    expect(on.metadata).toEqual({
      springboardSignInRequired: true,
      linkPreview: "x",
      springboardStaffOnly: true,
    });
    expect(isSpringboardStaffOnly(on)).toBe(true);
    expect(setSpringboardStaffOnly(on, false).metadata).toEqual(link.metadata);
    expect(isSpringboardStaffOnly({ type: "link", metadata: { springboardStaffOnly: true } })).toBe(false);
  });

  test("admits only staff account types, and nobody when none are configured", () => {
    const on = setSpringboardStaffOnly(link, true);
    expect(isRespondentAllowed(on, { accountType: "employee" }, ["employee"])).toBe(true);
    expect(isRespondentAllowed(on, { accountType: "student" }, ["employee"])).toBe(false);
    expect(isRespondentAllowed(on, { accountType: "employee" }, [])).toBe(false);
    expect(isRespondentAllowed(link, { accountType: "student" }, ["employee"])).toBe(true);
  });
});
