/**
 * The per-survey "Sign in with Springboard to answer" setting, and the response keys it writes.
 *
 * Stored as `springboardSignInRequired: true` in the survey's existing `metadata` JSON column
 * (`ZSurveyMetadata` keeps unknown keys), so it needs no migration. Client-safe: no server imports.
 */

export const SPRINGBOARD_SIGN_IN_METADATA_KEY = "springboardSignInRequired";

/**
 * The embedded field a respondent pass travels in (respondent-pass.ts). A survey that wants in-app
 * answers identified declares it, because the ingest contract keeps declared fields only.
 */
export const RESPONDENT_PASS_FIELD = "sb_pass";

/**
 * Keys the server writes into `response.data` from a verified cookie or pass. An address Springboard
 * vouches for also goes into core's own `verifiedEmail` key, so it shows up wherever verified emails
 * already do (response card, table, CSV export, follow-up recipients). The rest are Springboard's:
 * the account key is the identity, and `springboardEmail` is the address on file, verified or not.
 */
export const SPRINGBOARD_RESPONSE_KEYS = {
  email: "verifiedEmail",
  emailOnFile: "springboardEmail",
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

type TIdentitySurvey = TSurveyLike & {
  isAnonymizeResponsesEnabled?: boolean;
  embeddedFields?: { field: { source?: string }; link: { storageKey: string } }[] | null;
};

/** Whether the survey declares the respondent-pass field, i.e. its in-app answers can be identified. */
export const acceptsRespondentPass = (survey: TIdentitySurvey): boolean =>
  (survey.embeddedFields ?? []).some(
    ({ field, link }) => field.source === "ingested" && link.storageKey === RESPONDENT_PASS_FIELD
  );

/** Whether responses to this survey can carry a Springboard identity: sign-in or a pass, and not anonymized. */
export const recordsSpringboardIdentity = (survey: TIdentitySurvey): boolean =>
  !isSpringboardAnonymous(survey) && (isSpringboardSignInRequired(survey) || acceptsRespondentPass(survey));

/** Whether a survey's responses carry `verifiedEmail`: core's email verification, or a Springboard identity. */
export const hasVerifiedRespondentEmail = (
  survey: TIdentitySurvey & { isVerifyEmailEnabled?: boolean }
): boolean => Boolean(survey.isVerifyEmailEnabled) || recordsSpringboardIdentity(survey);

/** CSV/XLSX columns for the Springboard keys, after "Verified Email". */
export const SPRINGBOARD_EXPORT_HEADERS = [
  "Springboard Account Key",
  "Springboard Account Type",
  "Springboard Email",
];

/**
 * Core's "Anonymize responses" toggle. On such a survey Springboard never records who answered, even
 * when sign-in is required: the sign-in then only decides who may answer.
 */
export const isSpringboardAnonymous = (survey: { isAnonymizeResponsesEnabled?: boolean }): boolean =>
  survey.isAnonymizeResponsesEnabled === true;

/**
 * Context keys that would point an anonymous answer back at one person: anything ending in `_key` or
 * `_id` (run, test, session and account keys from the app), and a plain `email`.
 */
export const isIdentifyingContextKey = (key: string): boolean =>
  /(?:_key|_id|Key|Id)$/.test(key) || key.toLowerCase() === "email";
