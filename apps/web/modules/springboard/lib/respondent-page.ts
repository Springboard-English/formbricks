import "server-only";
import { cookies } from "next/headers";
import { getRespondentCookieName, verifyRespondentCookie } from "./respondent-cookie";
import { getSpringboardRespondentConfig } from "./runtime-config";

/** Query keys that belong to the sign-in round trip, not to the survey link. */
const GATE_ONLY_PARAMS = new Set(["springboardError"]);

/**
 * What the link-survey page needs to decide on the Springboard gate: whether this browser holds a
 * valid cookie for this survey, and where the sign-in button should go. The page is a convenience;
 * the response routes enforce the same cookie on their own.
 */
export const getSpringboardRespondentGateState = async (
  surveyId: string,
  searchParams: Record<string, string | string[] | undefined>
): Promise<{ signedIn: boolean; startUrl: string | null }> => {
  const config = getSpringboardRespondentConfig();
  if (!config) return { signedIn: false, startUrl: null };

  const cookieStore = await cookies();
  const identity = verifyRespondentCookie(
    cookieStore.get(getRespondentCookieName(surveyId))?.value,
    surveyId,
    config.cookieSecret
  );

  // The survey's own query string (single-use token, hidden fields, language) survives the round trip.
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(searchParams)) {
    if (GATE_ONLY_PARAMS.has(key) || value === undefined) continue;
    for (const entry of Array.isArray(value) ? value : [value]) query.append(key, entry);
  }
  const returnTo = `/s/${surveyId}${query.size > 0 ? `?${query.toString()}` : ""}`;
  const startUrl = `/api/springboard/respondent/start?${new URLSearchParams({ surveyId, returnTo }).toString()}`;

  return { signedIn: identity !== null, startUrl };
};
