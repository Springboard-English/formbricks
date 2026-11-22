/**
 * What a Hydra access token may reach on `/api/v3`, by path and method. Pure, so it is unit-testable
 * without the app.
 *
 * The scopes are Springboard's consent scopes, carried in the token's `scp` claim. Only surveys and
 * reading responses are open; every other v3 route stays session- or API-key-only.
 */

export const HYDRA_BEARER_SCOPES = {
  surveysRead: "surveys:read",
  surveysWrite: "surveys:write",
  responsesRead: "survey_responses:read",
} as const;

const SURVEYS_PATH = "/api/v3/surveys";
const RESPONSES_PATH = "/api/v3/responses";

const isUnder = (pathname: string, root: string): boolean =>
  pathname === root || pathname.startsWith(`${root}/`);

const isRead = (method: string): boolean => {
  const upper = method.toUpperCase();
  return upper === "GET" || upper === "HEAD";
};

/** The scope a Hydra token needs for this request, or `null` when the route is closed to Hydra tokens. */
export const requiredHydraBearerScope = (method: string, pathname: string): string | null => {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  if (isUnder(path, SURVEYS_PATH)) {
    return isRead(method) ? HYDRA_BEARER_SCOPES.surveysRead : HYDRA_BEARER_SCOPES.surveysWrite;
  }
  if (isUnder(path, RESPONSES_PATH) && isRead(method)) {
    return HYDRA_BEARER_SCOPES.responsesRead;
  }
  return null;
};

/** The token's scopes: Hydra's `scp` array, or an RFC 9068 space-separated `scope` string. */
export const readTokenScopes = (payload: Record<string, unknown>): string[] => {
  const { scp, scope } = payload;
  if (Array.isArray(scp)) {
    return scp.filter((value): value is string => typeof value === "string");
  }
  if (typeof scope === "string") {
    return scope.split(" ").filter(Boolean);
  }
  return [];
};
