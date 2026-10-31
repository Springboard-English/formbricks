"use client";

import { useTranslation } from "react-i18next";
import { TSurvey } from "@formbricks/types/surveys/types";
import {
  isSpringboardSignInRequired,
  setSpringboardSignInRequired,
} from "@/modules/springboard/lib/respondent-survey";
import { AdvancedOptionToggle } from "@/modules/ui/components/advanced-option-toggle";

interface SpringboardSignInToggleProps {
  localSurvey: TSurvey;
  setLocalSurvey: (survey: TSurvey | ((prev: TSurvey) => TSurvey)) => void;
  /** The respondent client is configured on this instance. */
  isAvailable: boolean;
}

/**
 * The survey-editor switch for "Sign in with Springboard to answer". Hidden when the instance has no
 * respondent client, unless the survey already has it on, so it can still be switched off.
 */
export const SpringboardSignInToggle = ({
  localSurvey,
  setLocalSurvey,
  isAvailable,
}: Readonly<SpringboardSignInToggleProps>) => {
  const { t } = useTranslation();
  const isChecked = isSpringboardSignInRequired(localSurvey);
  if (!isAvailable && !isChecked) return null;

  return (
    <AdvancedOptionToggle
      htmlId="springboardSignInRequired"
      isChecked={isChecked}
      onToggle={() =>
        setLocalSurvey((prev) => setSpringboardSignInRequired(prev, !isSpringboardSignInRequired(prev)))
      }
      title={t("workspace.surveys.edit.springboard_sign_in_required")}
      description={t("workspace.surveys.edit.springboard_sign_in_required_description")}
    />
  );
};
