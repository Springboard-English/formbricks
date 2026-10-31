import { logger } from "@formbricks/logger";
import { env } from "../../../lib/env";
import { throwEnvValidationError } from "../../../lib/env-validation-error";
import {
  type TSpringboardPassConfig,
  type TSpringboardRawEnv,
  type TSpringboardRespondentConfig,
  type TSpringboardStaffConfig,
  getSpringboardEnvWarnings,
  parseOffboardSecret,
  parsePassConfig,
  parseRespondentConfig,
  parseSessionMaxAgeSeconds,
  parseSingleWorkspace,
  parseStaffConfig,
  validateSpringboardEnv,
} from "./config";

/**
 * Springboard configuration read from the validated `env`. Relative imports (not `@/`) because the
 * container preflight bundles `scripts/docker/validate-env.ts`, which reaches this file.
 */
const raw = (): TSpringboardRawEnv => env;

export const getSpringboardStaffConfig = (): TSpringboardStaffConfig | null => parseStaffConfig(raw());

export const getSpringboardRespondentConfig = (): TSpringboardRespondentConfig | null =>
  parseRespondentConfig(raw());

export const getSpringboardPassConfig = (): TSpringboardPassConfig | null =>
  parsePassConfig(raw(), env.WEBAPP_URL);

export const getSpringboardSessionMaxAgeSeconds = (): number | null => parseSessionMaxAgeSeconds(raw());

export const getSpringboardOffboardSecret = (): string | null => parseOffboardSecret(raw());

export const isSpringboardSingleWorkspace = (): boolean => parseSingleWorkspace(raw());

/** Refuse to start on a half-configured Springboard feature. Never prints a value. */
export const assertSpringboardRuntimeConfiguration = (): void => {
  const issues = validateSpringboardEnv(raw());
  if (issues.length > 0) {
    throwEnvValidationError(issues.map((message) => ({ path: ["springboard"], message })));
  }
  for (const warning of getSpringboardEnvWarnings(raw())) {
    logger.warn(warning);
  }
};
