import "server-only";
import type { TResponseData } from "@formbricks/types/responses";
import { responses } from "@/app/lib/api/response";
import type { TRespondentIdentity } from "./respondent-cookie";
import { getRespondentCookieName, readCookie, verifyRespondentCookie } from "./respondent-cookie";
import { verifyRespondentPass } from "./respondent-pass";
import {
  RESPONDENT_PASS_FIELD,
  SPRINGBOARD_RESPONSE_KEYS,
  isIdentifyingContextKey,
  isSpringboardAnonymous,
  isSpringboardSignInRequired,
} from "./respondent-survey";
import { getSpringboardPassConfig, getSpringboardRespondentConfig } from "./runtime-config";

/**
 * The trust boundary for Springboard respondent identity, applied by the public response routes
 * (v1 and v2 POST, and the shared PUT) — never by the renderer alone, since those routes are public.
 *
 * The identity comes from the signed, survey-bound cookie ("Sign in with Springboard to answer" on a
 * link survey) or from a respondent pass the API signed (an in-app survey), and nothing else: the
 * request body's values under the same keys are overwritten on create and dropped on update, and the
 * pass itself is never stored. A survey that requires sign-in answers 403 without either. With no
 * respondent client configured such a survey cannot be answered at all (fail closed).
 *
 * On a survey with core's "Anonymize responses" on, no identity is ever recorded, the app's
 * identifying context keys are dropped and the page URL is cut to its origin.
 */

type TGateSurvey = {
  id: string;
  type?: string;
  metadata?: unknown;
  isAnonymizeResponsesEnabled?: boolean;
};

type TGateMeta = { url?: string } | undefined;

const forbidden = (surveyId: string) =>
  responses.forbiddenResponse("Survey requires Sign in with Springboard", true, { surveyId });

const readCookieIdentity = (surveyId: string, cookieHeader: string | null | undefined) => {
  const config = getSpringboardRespondentConfig();
  if (!config) return null;
  return verifyRespondentCookie(
    readCookie(cookieHeader, getRespondentCookieName(surveyId)),
    surveyId,
    config.cookieSecret
  );
};

const readPassIdentity = async (token: unknown): Promise<TRespondentIdentity | null> => {
  const config = getSpringboardPassConfig();
  return config ? verifyRespondentPass(token, config) : null;
};

/** Remove every key only the server may write, and the pass. Returns the pass as it arrived. */
const takeServerKeys = (data: TResponseData | undefined): unknown => {
  if (!data) return undefined;
  const pass = data[RESPONDENT_PASS_FIELD];
  delete data[RESPONDENT_PASS_FIELD];
  for (const key of Object.values(SPRINGBOARD_RESPONSE_KEYS)) {
    // `verifiedEmail` is core's key: the ingest contract already dropped any client value (it is a
    // forbidden field name), so whatever is here now was written by core's own gate and stays.
    if (key === SPRINGBOARD_RESPONSE_KEYS.email) continue;
    delete data[key];
  }
  return pass;
};

const anonymize = (data: TResponseData | undefined, meta: TGateMeta): void => {
  for (const key of Object.keys(data ?? {})) {
    if (data && isIdentifyingContextKey(key)) delete data[key];
  }
  if (meta?.url) {
    try {
      meta.url = new URL(meta.url).origin;
    } catch {
      delete meta.url;
    }
  }
};

const stamp = (data: TResponseData, identity: TRespondentIdentity): void => {
  if (identity.emailVerified && identity.email) {
    data[SPRINGBOARD_RESPONSE_KEYS.email] = identity.email;
  }
  if (identity.email) data[SPRINGBOARD_RESPONSE_KEYS.emailOnFile] = identity.email;
  data[SPRINGBOARD_RESPONSE_KEYS.accountKey] = identity.sub;
  data[SPRINGBOARD_RESPONSE_KEYS.accountType] = identity.accountType;
};

/** POST: stamp the verified identity into `responseData`. Must run as the last writer of those keys. */
export const enforceSpringboardRespondentGate = async ({
  survey,
  responseData,
  cookieHeader,
  meta,
}: {
  survey: TGateSurvey;
  responseData: TResponseData;
  cookieHeader: string | null | undefined;
  meta?: TGateMeta;
}): Promise<Response | null> => {
  const pass = takeServerKeys(responseData);
  const signInRequired = isSpringboardSignInRequired(survey);
  const identity =
    (signInRequired ? readCookieIdentity(survey.id, cookieHeader) : null) ??
    (pass === undefined ? null : await readPassIdentity(pass));
  if (signInRequired && !identity) return forbidden(survey.id);

  if (isSpringboardAnonymous(survey)) {
    anonymize(responseData, meta);
    return null;
  }
  if (identity) stamp(responseData, identity);
  return null;
};

/**
 * PUT (partial responses finishing): the same person, still signed in, and no rewriting the identity
 * the response was created with.
 */
export const enforceSpringboardRespondentGateOnUpdate = ({
  survey,
  existingResponseData,
  updateData,
  cookieHeader,
}: {
  survey: TGateSurvey;
  existingResponseData: TResponseData;
  updateData: TResponseData | undefined;
  cookieHeader: string | null | undefined;
}): Response | null => {
  takeServerKeys(updateData);
  const anonymous = isSpringboardAnonymous(survey);
  if (anonymous) anonymize(updateData, undefined);
  if (!isSpringboardSignInRequired(survey)) return null;

  const identity = readCookieIdentity(survey.id, cookieHeader);
  if (!identity) return forbidden(survey.id);
  // An anonymous response carries no key to compare against; the cookie alone still has to be valid.
  if (!anonymous && existingResponseData[SPRINGBOARD_RESPONSE_KEYS.accountKey] !== identity.sub) {
    return forbidden(survey.id);
  }
  return null;
};
