import { describe, expect, test } from "vitest";
import {
  getDiscoveryUrl,
  getSpringboardEnvWarnings,
  parseList,
  parsePassConfig,
  parseRespondentConfig,
  parseSessionMaxAgeSeconds,
  parseSingleWorkspace,
  parseStaffConfig,
  validateSpringboardEnv,
} from "./config";

const STAFF = {
  SPRINGBOARD_OIDC_ISSUER: "https://auth.springboard.vn/dev/",
  SPRINGBOARD_OIDC_CLIENT_ID: "staff-client",
  SPRINGBOARD_OIDC_CLIENT_SECRET: "staff-secret",
};

const RESPONDENT = {
  SPRINGBOARD_RESPONDENT_CLIENT_ID: "respondent-client",
  SPRINGBOARD_RESPONDENT_CLIENT_SECRET: "respondent-secret",
  SPRINGBOARD_RESPONDENT_COOKIE_SECRET: "c".repeat(32),
};

describe("Springboard config", () => {
  test("everything unset means every feature is off and nothing is reported", () => {
    expect(parseStaffConfig({})).toBeNull();
    expect(parseRespondentConfig({})).toBeNull();
    expect(parseSessionMaxAgeSeconds({})).toBeNull();
    expect(parseSingleWorkspace({})).toBe(false);
    expect(validateSpringboardEnv({})).toEqual([]);
    expect(getSpringboardEnvWarnings({})).toEqual([]);
  });

  test("staff config applies the documented defaults and normalizes the issuer", () => {
    expect(parseStaffConfig(STAFF)).toEqual({
      issuer: "https://auth.springboard.vn/dev",
      clientId: "staff-client",
      clientSecret: "staff-secret",
      allowedDomains: ["springboard.vn"],
      defaultRole: "member",
      staffAccountTypes: [],
    });
    expect(getDiscoveryUrl("https://auth.springboard.vn/dev/")).toBe(
      "https://auth.springboard.vn/dev/.well-known/openid-configuration"
    );
  });

  test("lists are trimmed, lower-cased and de-duplicated", () => {
    expect(parseList(" Employee, teacher ,,employee ")).toEqual(["employee", "teacher"]);
    expect(
      parseStaffConfig({
        ...STAFF,
        SPRINGBOARD_OIDC_ALLOWED_DOMAINS: "Springboard.vn, sb.edu.vn",
        SPRINGBOARD_OIDC_STAFF_ACCOUNT_TYPES: "Employee",
        SPRINGBOARD_OIDC_DEFAULT_ROLE: "manager",
      })
    ).toMatchObject({
      allowedDomains: ["springboard.vn", "sb.edu.vn"],
      staffAccountTypes: ["employee"],
      defaultRole: "manager",
    });
  });

  test("an unset staff account-type list is a warning, not a default", () => {
    expect(parseStaffConfig(STAFF)?.staffAccountTypes).toEqual([]);
    expect(getSpringboardEnvWarnings(STAFF)).toHaveLength(1);
  });

  test("partial staff configuration fails startup", () => {
    expect(validateSpringboardEnv({ SPRINGBOARD_OIDC_ISSUER: STAFF.SPRINGBOARD_OIDC_ISSUER })).toEqual([
      expect.stringContaining("SPRINGBOARD_OIDC_CLIENT_ID, SPRINGBOARD_OIDC_CLIENT_SECRET"),
    ]);
  });

  test("rejects a plain-http issuer, a bad role and a bad session length", () => {
    const issues = validateSpringboardEnv({
      ...STAFF,
      SPRINGBOARD_OIDC_ISSUER: "http://auth.springboard.vn",
      SPRINGBOARD_OIDC_DEFAULT_ROLE: "admin",
      SPRINGBOARD_SESSION_HOURS: "-1",
    });
    expect(issues).toHaveLength(3);
  });

  test("session lifetime: explicit hours, 12h default once sign-in is on, unchanged otherwise", () => {
    expect(parseSessionMaxAgeSeconds({ SPRINGBOARD_SESSION_HOURS: "8" })).toBe(8 * 3600);
    expect(parseSessionMaxAgeSeconds(STAFF)).toBe(12 * 3600);
    expect(parseSessionMaxAgeSeconds({})).toBeNull();
  });

  test("respondent config needs the issuer and its own client, distinct from the staff one", () => {
    expect(parseRespondentConfig(RESPONDENT)).toBeNull();
    expect(parseRespondentConfig({ ...STAFF, ...RESPONDENT })).toMatchObject({
      clientId: "respondent-client",
    });
    expect(
      validateSpringboardEnv({
        ...STAFF,
        ...RESPONDENT,
        SPRINGBOARD_RESPONDENT_CLIENT_ID: STAFF.SPRINGBOARD_OIDC_CLIENT_ID,
      })
    ).toEqual([expect.stringContaining("must differ")]);
    expect(validateSpringboardEnv(RESPONDENT)).toEqual([expect.stringContaining("SPRINGBOARD_OIDC_ISSUER")]);
  });

  test("short shared secrets fail startup", () => {
    const issues = validateSpringboardEnv({
      ...STAFF,
      ...RESPONDENT,
      SPRINGBOARD_RESPONDENT_COOKIE_SECRET: "short",
      SPRINGBOARD_OFFBOARD_SECRET: "short",
    });
    expect(issues).toHaveLength(2);
  });

  test("respondent passes need key and issuer together, a PEM key, and the instance's own origin", () => {
    const pem = String.raw`-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----`;
    const pass = {
      SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY: pem,
      SPRINGBOARD_RESPONDENT_PASS_ISSUER: "https://api.springboard.vn/",
    };
    expect(parsePassConfig(pass, "https://forms.springboard.vn/")).toEqual({
      publicKeyPem: "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
      issuer: "https://api.springboard.vn",
      audience: "https://forms.springboard.vn",
    });
    expect(parsePassConfig(pass, undefined)).toBeNull();
    expect(validateSpringboardEnv(pass)).toEqual([]);
    expect(validateSpringboardEnv({ SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY: pem })).toEqual([
      expect.stringContaining("both"),
    ]);
    expect(validateSpringboardEnv({ ...pass, SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY: "abc" })).toEqual([
      expect.stringContaining("PEM"),
    ]);
  });

  test("single-workspace lock is on only for exactly 1", () => {
    expect(parseSingleWorkspace({ SPRINGBOARD_SINGLE_WORKSPACE: "1" })).toBe(true);
    expect(parseSingleWorkspace({ SPRINGBOARD_SINGLE_WORKSPACE: "0" })).toBe(false);
    expect(validateSpringboardEnv({ SPRINGBOARD_SINGLE_WORKSPACE: "yes" })).toHaveLength(1);
  });
});
