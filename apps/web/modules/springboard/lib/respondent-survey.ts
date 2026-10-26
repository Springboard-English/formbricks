/**
 * The per-survey "Sign in with Springboard to answer" setting, and the response keys it writes.
 *
 * Stored as `springboardSignInRequired: true` in the survey's existing `metadata` JSON column
 * (`ZSurveyMetadata` keeps unknown keys), so it needs no migration. Client-safe: no server imports.
 */

export const SPRINGBOARD_SIGN_IN_METADATA_KEY = "springboardSignInRequired";

/**
 * Keys the server writes into `response.data` from the verified cookie. The address goes into core's
 * own `verifiedEmail` key, so it shows up wherever verified emails already do (response card,
 * table, CSV export, follow-up recipients). The other two are Springboard's.
 */
export const SPRINGBOARD_RESPONSE_KEYS = {
  email: "verifiedEmail",
  accountKey: "springboardAccountKey",
  accountType: "springboardAccountType",
} as const;

type TSurveyLike = { type?: string; metadata?: unknown };

export const isSpringboardSignInRequired = (survey: TSurveyLike): boolean => {
  if (survey.type !== "link") return false;
  const metadata = survey.metadata;
  return (
    metadata !== null &&
    typeof metadata === "object" &&
    (metadata as Record<string, unknown>)[SPRINGBOARD_SIGN_IN_METADATA_KEY] === true
  );
};

export const setSpringboardSignInRequired = <T extends { metadata?: unknown }>(
  survey: T,
  required: boolean
): T => {
  const current =
    survey.metadata !== null && typeof survey.metadata === "object"
      ? (survey.metadata as Record<string, unknown>)
      : {};
  const { [SPRINGBOARD_SIGN_IN_METADATA_KEY]: _previous, ...rest } = current;
  return { ...survey, metadata: required ? { ...rest, [SPRINGBOARD_SIGN_IN_METADATA_KEY]: true } : rest };
};

/** Whether a survey's responses carry `verifiedEmail`: core's email verification, or Springboard sign-in. */
export const hasVerifiedRespondentEmail = (
  survey: TSurveyLike & { isVerifyEmailEnabled?: boolean }
): boolean => Boolean(survey.isVerifyEmailEnabled) || isSpringboardSignInRequired(survey);

/** CSV/XLSX columns for the two Springboard keys, after "Verified Email". */
export const SPRINGBOARD_EXPORT_HEADERS = ["Springboard Account Key", "Springboard Account Type"];
