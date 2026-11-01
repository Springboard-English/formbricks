import "server-only";
import { createCacheKey } from "@formbricks/cache";
import { prisma } from "@formbricks/database";
import { cache } from "@/lib/cache";
import { SPRINGBOARD_RESPONSE_KEYS } from "./respondent-survey";

/**
 * Spend a pass by its id: true for the first use only. The key outlives the pass by a moment, so it
 * cannot expire while the pass still verifies. With Redis unavailable nothing can be proven unspent,
 * so the pass counts as spent and the answer saves without identity.
 */
export const spendRespondentPass = async (jti: string, expiresAtSeconds: number): Promise<boolean> => {
  const ttlMs = Math.max(expiresAtSeconds * 1000 - Date.now(), 0) + 60_000;
  const claimed = await cache.tryLock(createCacheKey.springboard.respondentPass(jti), "1", ttlMs);
  return claimed.ok && claimed.data;
};

/** Whether this account already has a response on this survey. Read per survey, never across them. */
export const hasRespondedToSurvey = async (surveyId: string, accountKey: string): Promise<boolean> => {
  const response = await prisma.response.findFirst({
    where: { surveyId, data: { path: [SPRINGBOARD_RESPONSE_KEYS.accountKey], equals: accountKey } },
    select: { id: true },
  });
  return response !== null;
};
