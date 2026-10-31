import type { TOrganizationRole } from "@formbricks/types/memberships";

/**
 * Springboard's configuration, parsed from raw env values.
 *
 * Pure on purpose — no `env` import, no `server-only` — so every rule here is unit-testable and the
 * container preflight (`scripts/docker/validate-env.ts`) can run it without loading the app. The
 * runtime getters that feed it from `lib/env.ts` live in `runtime-config.ts`.
 *
 * Every feature is off unless its variables are set, and an unset feature changes nothing.
 */

/** Better Auth provider id. Never `openid`: that id belongs to the licence-gated upstream provider. */
export const SPRINGBOARD_PROVIDER_ID = "springboard";

export const DEFAULT_ALLOWED_DOMAINS = ["springboard.vn"];
export const DEFAULT_STAFF_ROLE: TOrganizationRole = "member";
export const DEFAULT_SESSION_HOURS = 12;

const ORGANIZATION_ROLES: readonly TOrganizationRole[] = ["owner", "manager", "member", "billing"];

export type TSpringboardRawEnv = Partial<
  Record<
    | "SPRINGBOARD_OIDC_ISSUER"
    | "SPRINGBOARD_OIDC_CLIENT_ID"
    | "SPRINGBOARD_OIDC_CLIENT_SECRET"
    | "SPRINGBOARD_OIDC_ALLOWED_DOMAINS"
    | "SPRINGBOARD_OIDC_DEFAULT_ROLE"
    | "SPRINGBOARD_OIDC_STAFF_ACCOUNT_TYPES"
    | "SPRINGBOARD_SESSION_HOURS"
    | "SPRINGBOARD_OFFBOARD_SECRET"
    | "SPRINGBOARD_RESPONDENT_CLIENT_ID"
    | "SPRINGBOARD_RESPONDENT_CLIENT_SECRET"
    | "SPRINGBOARD_RESPONDENT_COOKIE_SECRET"
    | "SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY"
    | "SPRINGBOARD_RESPONDENT_PASS_ISSUER"
    | "SPRINGBOARD_SINGLE_WORKSPACE",
    string | undefined
  >
>;

export type TSpringboardStaffConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  allowedDomains: string[];
  defaultRole: TOrganizationRole;
  /** Empty when unset: the provider is still offered, and every sign-in is refused (fail closed). */
  staffAccountTypes: string[];
};

export type TSpringboardRespondentConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  cookieSecret: string;
};

/** How to verify a respondent pass from Springboard's API: its RS256 public key, issuer and audience. */
export type TSpringboardPassConfig = {
  publicKeyPem: string;
  issuer: string;
  /** This instance's own origin (WEBAPP_URL): a pass minted for anywhere else is refused. */
  audience: string;
};

const clean = (value: string | undefined): string | undefined => {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
};

/** Comma list → trimmed, lower-cased, de-duplicated, blanks dropped. */
export const parseList = (value: string | undefined): string[] => [
  ...new Set(
    (value ?? "")
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean)
  ),
];

/** The issuer without a trailing slash, so `${issuer}/.well-known/…` never doubles it. */
export const normalizeIssuer = (issuer: string): string => issuer.replace(/\/+$/, "");

export const getDiscoveryUrl = (issuer: string): string =>
  `${normalizeIssuer(issuer)}/.well-known/openid-configuration`;

const STAFF_KEYS = [
  "SPRINGBOARD_OIDC_ISSUER",
  "SPRINGBOARD_OIDC_CLIENT_ID",
  "SPRINGBOARD_OIDC_CLIENT_SECRET",
] as const;

const RESPONDENT_KEYS = [
  "SPRINGBOARD_RESPONDENT_CLIENT_ID",
  "SPRINGBOARD_RESPONDENT_CLIENT_SECRET",
  "SPRINGBOARD_RESPONDENT_COOKIE_SECRET",
] as const;

/** `null` = staff sign-in is off. Partial configuration is reported by `validateSpringboardEnv`. */
export const parseStaffConfig = (raw: TSpringboardRawEnv): TSpringboardStaffConfig | null => {
  const issuer = clean(raw.SPRINGBOARD_OIDC_ISSUER);
  const clientId = clean(raw.SPRINGBOARD_OIDC_CLIENT_ID);
  const clientSecret = clean(raw.SPRINGBOARD_OIDC_CLIENT_SECRET);
  if (!issuer || !clientId || !clientSecret) return null;

  const allowedDomains = parseList(raw.SPRINGBOARD_OIDC_ALLOWED_DOMAINS);
  const role = clean(raw.SPRINGBOARD_OIDC_DEFAULT_ROLE) as TOrganizationRole | undefined;

  return {
    issuer: normalizeIssuer(issuer),
    clientId,
    clientSecret,
    allowedDomains: allowedDomains.length > 0 ? allowedDomains : DEFAULT_ALLOWED_DOMAINS,
    defaultRole: role && ORGANIZATION_ROLES.includes(role) ? role : DEFAULT_STAFF_ROLE,
    staffAccountTypes: parseList(raw.SPRINGBOARD_OIDC_STAFF_ACCOUNT_TYPES),
  };
};

/**
 * `null` = respondent sign-in is off. It shares the staff issuer (one Hydra) but never the client: the
 * staff client is allow-listed to staff, the respondent client is open to every account type.
 */
export const parseRespondentConfig = (raw: TSpringboardRawEnv): TSpringboardRespondentConfig | null => {
  const issuer = clean(raw.SPRINGBOARD_OIDC_ISSUER);
  const clientId = clean(raw.SPRINGBOARD_RESPONDENT_CLIENT_ID);
  const clientSecret = clean(raw.SPRINGBOARD_RESPONDENT_CLIENT_SECRET);
  const cookieSecret = clean(raw.SPRINGBOARD_RESPONDENT_COOKIE_SECRET);
  if (!issuer || !clientId || !clientSecret || !cookieSecret) return null;
  return { issuer: normalizeIssuer(issuer), clientId, clientSecret, cookieSecret };
};

/**
 * `null` = respondent passes are ignored. A PEM's `\n` escapes are unfolded, because a multi-line key
 * usually arrives through a one-line env var.
 */
export const parsePassConfig = (
  raw: TSpringboardRawEnv,
  webappUrl: string | undefined
): TSpringboardPassConfig | null => {
  const publicKeyPem = clean(raw.SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY)?.replaceAll(String.raw`\n`, "\n");
  const issuer = clean(raw.SPRINGBOARD_RESPONDENT_PASS_ISSUER);
  const audience = clean(webappUrl);
  if (!publicKeyPem || !issuer || !audience) return null;
  return { publicKeyPem, issuer: normalizeIssuer(issuer), audience: normalizeIssuer(audience) };
};

/** Session lifetime in seconds, or `null` to keep the core default (`SESSION_MAX_AGE`). */
export const parseSessionMaxAgeSeconds = (raw: TSpringboardRawEnv): number | null => {
  const hours = clean(raw.SPRINGBOARD_SESSION_HOURS);
  if (hours !== undefined) {
    const parsed = Number(hours);
    return Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed * 3600) : null;
  }
  // Unset: 12 hours once Springboard sign-in is on, otherwise no change at all.
  return parseStaffConfig(raw) ? DEFAULT_SESSION_HOURS * 3600 : null;
};

export const parseOffboardSecret = (raw: TSpringboardRawEnv): string | null =>
  clean(raw.SPRINGBOARD_OFFBOARD_SECRET) ?? null;

export const parseSingleWorkspace = (raw: TSpringboardRawEnv): boolean =>
  clean(raw.SPRINGBOARD_SINGLE_WORKSPACE) === "1";

const MIN_SECRET_LENGTH = 32;

/**
 * Startup checks. Returns human-readable problems (never the values). Fails only on configuration
 * that would otherwise half-work; a feature whose variables are all unset is simply off.
 */
export const validateSpringboardEnv = (raw: TSpringboardRawEnv): string[] => {
  const issues: string[] = [];

  const setStaff = STAFF_KEYS.filter((key) => clean(raw[key]));
  if (setStaff.length > 0 && setStaff.length < STAFF_KEYS.length) {
    const missing = STAFF_KEYS.filter((key) => !clean(raw[key]));
    issues.push(`Springboard sign-in is partially configured: also set ${missing.join(", ")}.`);
  }

  const issuer = clean(raw.SPRINGBOARD_OIDC_ISSUER);
  if (issuer) {
    try {
      const url = new URL(issuer);
      if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
        issues.push("SPRINGBOARD_OIDC_ISSUER must be an https URL.");
      }
    } catch {
      issues.push("SPRINGBOARD_OIDC_ISSUER must be a URL.");
    }
  }

  const role = clean(raw.SPRINGBOARD_OIDC_DEFAULT_ROLE);
  if (role && !ORGANIZATION_ROLES.includes(role as TOrganizationRole)) {
    issues.push(`SPRINGBOARD_OIDC_DEFAULT_ROLE must be one of ${ORGANIZATION_ROLES.join(", ")}.`);
  }

  const hours = clean(raw.SPRINGBOARD_SESSION_HOURS);
  if (hours !== undefined && !(Number(hours) > 0 && Number(hours) <= 24 * 30)) {
    issues.push("SPRINGBOARD_SESSION_HOURS must be a number of hours between 0 and 720.");
  }

  const offboardSecret = clean(raw.SPRINGBOARD_OFFBOARD_SECRET);
  if (offboardSecret && offboardSecret.length < MIN_SECRET_LENGTH) {
    issues.push(`SPRINGBOARD_OFFBOARD_SECRET must be at least ${MIN_SECRET_LENGTH} characters.`);
  }

  const setRespondent = RESPONDENT_KEYS.filter((key) => clean(raw[key]));
  if (setRespondent.length > 0) {
    if (setRespondent.length < RESPONDENT_KEYS.length) {
      const missing = RESPONDENT_KEYS.filter((key) => !clean(raw[key]));
      issues.push(`Springboard respondent sign-in is partially configured: also set ${missing.join(", ")}.`);
    }
    if (!issuer) {
      issues.push("Springboard respondent sign-in needs SPRINGBOARD_OIDC_ISSUER.");
    }
    const staffClientId = clean(raw.SPRINGBOARD_OIDC_CLIENT_ID);
    if (staffClientId && staffClientId === clean(raw.SPRINGBOARD_RESPONDENT_CLIENT_ID)) {
      issues.push("SPRINGBOARD_RESPONDENT_CLIENT_ID must differ from SPRINGBOARD_OIDC_CLIENT_ID.");
    }
    const cookieSecret = clean(raw.SPRINGBOARD_RESPONDENT_COOKIE_SECRET);
    if (cookieSecret && cookieSecret.length < MIN_SECRET_LENGTH) {
      issues.push(`SPRINGBOARD_RESPONDENT_COOKIE_SECRET must be at least ${MIN_SECRET_LENGTH} characters.`);
    }
  }

  const passKey = clean(raw.SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY);
  const passIssuer = clean(raw.SPRINGBOARD_RESPONDENT_PASS_ISSUER);
  if (Boolean(passKey) !== Boolean(passIssuer)) {
    issues.push(
      "Springboard respondent passes need both SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY and SPRINGBOARD_RESPONDENT_PASS_ISSUER."
    );
  }
  if (passKey && !passKey.includes("BEGIN PUBLIC KEY")) {
    issues.push("SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY must be a PEM public key (BEGIN PUBLIC KEY).");
  }

  const singleWorkspace = clean(raw.SPRINGBOARD_SINGLE_WORKSPACE);
  if (singleWorkspace && singleWorkspace !== "1" && singleWorkspace !== "0") {
    issues.push("SPRINGBOARD_SINGLE_WORKSPACE must be 1 or 0.");
  }

  return issues;
};

/** Startup warnings: configuration that boots but will refuse every sign-in. */
export const getSpringboardEnvWarnings = (raw: TSpringboardRawEnv): string[] => {
  const staff = parseStaffConfig(raw);
  if (staff && staff.staffAccountTypes.length === 0) {
    return [
      "SPRINGBOARD_OIDC_STAFF_ACCOUNT_TYPES is unset, so every Springboard sign-in is refused until it lists the staff account types.",
    ];
  }
  return [];
};
