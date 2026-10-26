"use client";

import { MailIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { TResponseData } from "@formbricks/types/responses";
import { SPRINGBOARD_RESPONSE_KEYS } from "@/modules/springboard/lib/respondent-survey";

interface VerifiedEmailProps {
  responseData: TResponseData;
}
export const VerifiedEmail = ({ responseData }: VerifiedEmailProps) => {
  const { t } = useTranslation();
  return (
    <div>
      <p className="flex items-center gap-x-2 text-sm text-slate-500">
        <MailIcon className="size-4" />
        <span>{t("common.verified_email")}</span>
      </p>
      <p className="ph-no-capture my-1 font-semibold text-slate-700">
        {typeof responseData["verifiedEmail"] === "string" ? responseData["verifiedEmail"] : ""}
      </p>
      {/* Springboard fork: set only on surveys that require Sign in with Springboard. */}
      {typeof responseData[SPRINGBOARD_RESPONSE_KEYS.accountKey] === "string" && (
        <p className="ph-no-capture text-xs text-slate-500">
          {t("common.springboard_account", {
            type: String(responseData[SPRINGBOARD_RESPONSE_KEYS.accountType] ?? ""),
            key: String(responseData[SPRINGBOARD_RESPONSE_KEYS.accountKey]),
          })}
        </p>
      )}
    </div>
  );
};
