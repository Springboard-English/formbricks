import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Signed, survey-bound cookies for the respondent flow. HMAC-SHA256 over a base64url JSON payload,
 * keyed by SPRINGBOARD_RESPONDENT_COOKIE_SECRET. Holds only what a response is allowed to carry —
 * address, account key (`sub`) and account type — never a token.
 */

export const RESPONDENT_COOKIE_MAX_AGE_SECONDS = 2 * 60 * 60;
export const RESPONDENT_FLOW_COOKIE_MAX_AGE_SECONDS = 10 * 60;
export const RESPONDENT_FLOW_COOKIE_NAME = "sb_respondent_flow";

/** One cookie per survey, so signing in for one survey says nothing about another. */
export const getRespondentCookieName = (surveyId: string): string => `sb_respondent_${surveyId}`;

export type TRespondentIdentity = { email: string; sub: string; accountType: string };

export type TRespondentFlowState = {
  surveyId: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
};

type TEnvelope<T> = { v: 1; purpose: "identity" | "flow"; sid: string; exp: number; data: T };

const mac = (secret: string, body: string): string =>
  createHmac("sha256", secret).update(body).digest("base64url");

const sign = <T>(envelope: TEnvelope<T>, secret: string): string => {
  const body = Buffer.from(JSON.stringify(envelope)).toString("base64url");
  return `${body}.${mac(secret, body)}`;
};

const open = <T>(
  value: string | undefined | null,
  secret: string,
  purpose: TEnvelope<T>["purpose"],
  surveyId: string | null,
  now: number
): T | null => {
  if (!value) return null;
  const [body, signature, extra] = value.split(".");
  if (!body || !signature || extra !== undefined) return null;

  const expected = Buffer.from(mac(secret, body));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;

  let envelope: TEnvelope<T>;
  try {
    envelope = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (envelope?.v !== 1 || envelope.purpose !== purpose) return null;
  if (typeof envelope.exp !== "number" || envelope.exp <= Math.floor(now / 1000)) return null;
  if (surveyId !== null && envelope.sid !== surveyId) return null;
  return envelope.data;
};

export const signRespondentCookie = (
  identity: TRespondentIdentity,
  surveyId: string,
  secret: string,
  now = Date.now()
): string =>
  sign(
    {
      v: 1,
      purpose: "identity",
      sid: surveyId,
      exp: Math.floor(now / 1000) + RESPONDENT_COOKIE_MAX_AGE_SECONDS,
      data: { email: identity.email, sub: identity.sub, accountType: identity.accountType },
    },
    secret
  );

/** The identity, or `null` for a missing, tampered, expired or other-survey cookie. */
export const verifyRespondentCookie = (
  value: string | undefined | null,
  surveyId: string,
  secret: string,
  now = Date.now()
): TRespondentIdentity | null => {
  const data = open<TRespondentIdentity>(value, secret, "identity", surveyId, now);
  if (
    !data ||
    typeof data.email !== "string" ||
    typeof data.sub !== "string" ||
    typeof data.accountType !== "string"
  ) {
    return null;
  }
  return data;
};

export const signRespondentFlowCookie = (
  flow: TRespondentFlowState,
  secret: string,
  now = Date.now()
): string =>
  sign(
    {
      v: 1,
      purpose: "flow",
      sid: flow.surveyId,
      exp: Math.floor(now / 1000) + RESPONDENT_FLOW_COOKIE_MAX_AGE_SECONDS,
      data: flow,
    },
    secret
  );

export const verifyRespondentFlowCookie = (
  value: string | undefined | null,
  secret: string,
  now = Date.now()
): TRespondentFlowState | null => open<TRespondentFlowState>(value, secret, "flow", null, now);

/** Read one cookie out of a raw `Cookie` header. */
export const readCookie = (cookieHeader: string | null | undefined, name: string): string | undefined => {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }
  return undefined;
};
