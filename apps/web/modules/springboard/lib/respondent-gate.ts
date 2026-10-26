import "server-only";
import type { TResponseData } from "@formbricks/types/responses";
import { responses } from "@/app/lib/api/response";
import { getRespondentCookieName, readCookie, verifyRespondentCookie } from "./respondent-cookie";
import { SPRINGBOARD_RESPONSE_KEYS, isSpringboardSignInRequired } from "./respondent-survey";
import { getSpringboardRespondentConfig } from "./runtime-config";

/**
 * The trust boundary for "Sign in with Springboard to answer", applied by the public response
 * routes (v1 and v2 POST, and the shared PUT) — never by the renderer alone, since those routes are
 * public and the page is only a convenience.
 *
 * The identity comes from the signed, survey-bound cookie and nothing else: whatever the request
 * body says under the same keys is overwritten on create and dropped on update. Without a valid
 * cookie a survey that requires sign-in answers 403. If the instance has no respondent client
 * configured, such a survey cannot be answered at all (fail closed), rather than silently dropping
 * the requirement.
 */

type TGateSurvey = { id: string; type?: string; metadata?: unknown };

const forbidden = (surveyId: string) =>
  responses.forbiddenResponse("Survey requires Sign in with Springboard", true, { surveyId });

const readIdentity = (surveyId: string, cookieHeader: string | null | undefined) => {
  const config = getSpringboardRespondentConfig();
  if (!config) return null;
  return verifyRespondentCookie(
    readCookie(cookieHeader, getRespondentCookieName(surveyId)),
    surveyId,
    config.cookieSecret
  );
};

const stripSpringboardKeys = (data: TResponseData | undefined): void => {
  if (!data) return;
  for (const key of Object.values(SPRINGBOARD_RESPONSE_KEYS)) {
    delete data[key];
  }
};

/** POST: stamp the verified identity into `responseData`. Must run as the last writer of those keys. */
export const enforceSpringboardRespondentGate = ({
  survey,
  responseData,
  cookieHeader,
}: {
  survey: TGateSurvey;
  responseData: TResponseData;
  cookieHeader: string | null | undefined;
}): Response | null => {
  if (!isSpringboardSignInRequired(survey)) return null;

  const identity = readIdentity(survey.id, cookieHeader);
  stripSpringboardKeys(responseData);
  if (!identity) return forbidden(survey.id);

  responseData[SPRINGBOARD_RESPONSE_KEYS.email] = identity.email;
  responseData[SPRINGBOARD_RESPONSE_KEYS.accountKey] = identity.sub;
  responseData[SPRINGBOARD_RESPONSE_KEYS.accountType] = identity.accountType;
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
  if (!isSpringboardSignInRequired(survey)) return null;

  stripSpringboardKeys(updateData);
  const identity = readIdentity(survey.id, cookieHeader);
  if (!identity) return forbidden(survey.id);
  if (existingResponseData[SPRINGBOARD_RESPONSE_KEYS.accountKey] !== identity.sub) {
    return forbidden(survey.id);
  }
  return null;
};
