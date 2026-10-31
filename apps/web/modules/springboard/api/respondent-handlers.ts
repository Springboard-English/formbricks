import "server-only";
import { NextResponse } from "next/server";
import { logger } from "@formbricks/logger";
import { TooManyRequestsError } from "@formbricks/types/errors";
import { getPublicDomain } from "@/lib/getPublicUrl";
import { getSurvey } from "@/lib/survey/service";
import { USE_SECURE_COOKIES } from "@/modules/auth/lib/auth-cookies";
import { applyIPRateLimit } from "@/modules/core/rate-limit/helpers";
import { getOidcProvider } from "@/modules/springboard/lib/oidc";
import {
  RESPONDENT_COOKIE_MAX_AGE_SECONDS,
  RESPONDENT_FLOW_COOKIE_MAX_AGE_SECONDS,
  RESPONDENT_FLOW_COOKIE_NAME,
  getRespondentCookieName,
  readCookie,
  signRespondentCookie,
  signRespondentFlowCookie,
  verifyRespondentFlowCookie,
} from "@/modules/springboard/lib/respondent-cookie";
import {
  buildRespondentAuthorization,
  completeRespondentCallback,
  sanitizeReturnTo,
} from "@/modules/springboard/lib/respondent-flow";
import { isSpringboardSignInRequired } from "@/modules/springboard/lib/respondent-survey";
import { getSpringboardRespondentConfig } from "@/modules/springboard/lib/runtime-config";

/**
 * `GET /api/springboard/respondent/start?surveyId=…&returnTo=…` → Hydra (RESPONDENT client), and
 * `GET /api/springboard/respondent/callback` → back to the survey with a signed, survey-bound cookie.
 * Neither ever touches Better Auth, users, accounts or sessions.
 */

const RATE_LIMIT = { interval: 60, allowedPerInterval: 30, namespace: "springboard:respondent" };

export const getRespondentCallbackUrl = (): string =>
  `${getPublicDomain().replace(/\/+$/, "")}/api/springboard/respondent/callback`;

const cookieOptions = (maxAge: number) => ({
  httpOnly: true,
  secure: USE_SECURE_COOKIES,
  sameSite: "lax" as const,
  path: "/",
  maxAge,
});

const redirectTo = (path: string) => {
  const response = NextResponse.redirect(new URL(path, getPublicDomain()), 303);
  response.headers.set("Cache-Control", "no-store");
  return response;
};

const withError = (path: string, error: string): string => {
  const url = new URL(path, "https://placeholder.invalid");
  url.searchParams.set("springboardError", error);
  return `${url.pathname}${url.search}`;
};

const isRateLimited = async (): Promise<boolean> => {
  try {
    await applyIPRateLimit(RATE_LIMIT);
    return false;
  } catch (error) {
    if (error instanceof TooManyRequestsError) return true;
    throw error;
  }
};

export const handleRespondentStart = async (request: Request): Promise<Response> => {
  const config = getSpringboardRespondentConfig();
  if (!config) return NextResponse.json({ error: "not_found" }, { status: 404 });
  if (await isRateLimited()) return NextResponse.json({ error: "too_many_requests" }, { status: 429 });

  const params = new URL(request.url).searchParams;
  const surveyId = params.get("surveyId") ?? "";
  const survey = /^[a-z0-9]{1,64}$/i.test(surveyId) ? await getSurvey(surveyId) : null;
  if (!survey || !isSpringboardSignInRequired(survey)) {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }

  try {
    const { metadata } = await getOidcProvider(config.issuer);
    const { authorizationUrl, flow } = await buildRespondentAuthorization({
      config,
      metadata,
      redirectUri: getRespondentCallbackUrl(),
      surveyId,
      returnTo: sanitizeReturnTo(surveyId, params.get("returnTo")),
    });
    const response = NextResponse.redirect(authorizationUrl, 303);
    response.headers.set("Cache-Control", "no-store");
    response.cookies.set(
      RESPONDENT_FLOW_COOKIE_NAME,
      signRespondentFlowCookie(flow, config.cookieSecret),
      cookieOptions(RESPONDENT_FLOW_COOKIE_MAX_AGE_SECONDS)
    );
    return response;
  } catch (error) {
    logger.error({ error, surveyId }, "Springboard respondent sign-in could not start");
    return redirectTo(withError(`/s/${surveyId}`, "respondent_unavailable"));
  }
};

export const handleRespondentCallback = async (request: Request): Promise<Response> => {
  const config = getSpringboardRespondentConfig();
  if (!config) return NextResponse.json({ error: "not_found" }, { status: 404 });
  if (await isRateLimited()) return NextResponse.json({ error: "too_many_requests" }, { status: 429 });

  const flow = verifyRespondentFlowCookie(
    readCookie(request.headers.get("cookie"), RESPONDENT_FLOW_COOKIE_NAME),
    config.cookieSecret
  );
  if (!flow) {
    return NextResponse.json({ error: "respondent_invalid_state" }, { status: 400 });
  }

  let result: Awaited<ReturnType<typeof completeRespondentCallback>>;
  try {
    const { metadata, jwks } = await getOidcProvider(config.issuer);
    result = await completeRespondentCallback({
      config,
      metadata,
      jwks,
      redirectUri: getRespondentCallbackUrl(),
      flow,
      query: new URL(request.url).searchParams,
    });
  } catch (error) {
    logger.error({ error, surveyId: flow.surveyId }, "Springboard respondent callback failed");
    result = { ok: false, error: "respondent_token_exchange_failed" };
  }

  const response = redirectTo(result.ok ? flow.returnTo : withError(flow.returnTo, result.error));
  response.cookies.set(RESPONDENT_FLOW_COOKIE_NAME, "", cookieOptions(0));
  if (result.ok) {
    response.cookies.set(
      getRespondentCookieName(flow.surveyId),
      signRespondentCookie(result.identity, flow.surveyId, config.cookieSecret),
      cookieOptions(RESPONDENT_COOKIE_MAX_AGE_SECONDS)
    );
  } else {
    logger.warn({ surveyId: flow.surveyId, code: result.error }, "Springboard respondent sign-in refused");
  }
  return response;
};
