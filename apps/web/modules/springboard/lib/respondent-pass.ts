import { jwtVerify } from "jose";
import { createPublicKey } from "node:crypto";
import type { TSpringboardPassConfig } from "./config";
import type { TRespondentIdentity } from "./respondent-cookie";
import { identityFromClaims } from "./respondent-flow";

/**
 * Respondent passes: a ten-minute RS256 token Springboard's API signs for one signed-in person
 * (`POST /v2/users/me/respondent-pass`), so an in-app survey can record who answered without a
 * sign-in redirect. The app sends it as the embedded field `sb_pass` (`RESPONDENT_PASS_FIELD`); the
 * server verifies it here and never stores it.
 */

export const RESPONDENT_PASS_TYPE = "respondent_pass";
/** The API mints ten-minute passes; anything claiming a longer life was not minted by it. */
export const RESPONDENT_PASS_MAX_LIFETIME_SECONDS = 10 * 60;

/** The identity a pass vouches for, or `null` for any pass that is not exactly what the API mints. */
export const verifyRespondentPass = async (
  token: unknown,
  config: TSpringboardPassConfig,
  now = new Date()
): Promise<TRespondentIdentity | null> => {
  if (typeof token !== "string" || !token) return null;
  try {
    const { payload } = await jwtVerify(token, createPublicKey(config.publicKeyPem), {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: ["RS256"],
      currentDate: now,
      requiredClaims: ["sub", "exp", "iat"],
    });
    if (payload.typ !== RESPONDENT_PASS_TYPE) return null;
    if ((payload.exp ?? 0) - (payload.iat ?? 0) > RESPONDENT_PASS_MAX_LIFETIME_SECONDS) return null;
    const result = identityFromClaims(payload);
    return result.ok ? result.identity : null;
  } catch {
    return null;
  }
};
