import { describe, expect, test } from "vitest";
import { shouldAutoStartSpringboardSignIn } from "./sso-redirect";

const base = {
  springboardSignInEnabled: true,
  emailAuthEnabled: false,
  oauthError: undefined,
  signedOut: undefined,
};

describe("login page auto-start of Springboard sign-in", () => {
  test("starts once Springboard is the only way in", () => {
    expect(shouldAutoStartSpringboardSignIn(base)).toBe(true);
  });

  test.each([
    ["Springboard sign-in is not configured", { springboardSignInEnabled: false }],
    ["email sign-in is still on", { emailAuthEnabled: true }],
    ["the last sign-in was refused", { oauthError: "springboard_not_staff" }],
    ["the person just signed out", { signedOut: "1" }],
  ])("does not start when %s", (_label, override) => {
    expect(shouldAutoStartSpringboardSignIn({ ...base, ...override })).toBe(false);
  });
});
