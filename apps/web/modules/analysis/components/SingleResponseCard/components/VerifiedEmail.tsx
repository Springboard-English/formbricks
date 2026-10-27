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
  const verifiedEmail =
    typeof responseData["verifiedEmail"] === "string" ? responseData["verifiedEmail"] : "";
  const emailOnFile = responseData[SPRINGBOARD_RESPONSE_KEYS.emailOnFile];
  return (
    <div>
      {verifiedEmail && (
        <>
          <p className="flex items-center gap-x-2 text-sm text-slate-500">
            <MailIcon className="size-4" />
            <span>{t("common.verified_email")}</span>
          </p>
          <p className="ph-no-capture my-1 font-semibold text-slate-700">{verifiedEmail}</p>
        </>
      )}
      {/* Springboard fork: set on answers identified by Springboard sign-in or a respondent pass. */}
      {typeof responseData[SPRINGBOARD_RESPONSE_KEYS.accountKey] === "string" && (
        <p className="ph-no-capture text-xs text-slate-500">
          {t("common.springboard_account", {
            type: String(responseData[SPRINGBOARD_RESPONSE_KEYS.accountType] ?? ""),
            key: String(responseData[SPRINGBOARD_RESPONSE_KEYS.accountKey]),
          })}
        </p>
      )}
      {!verifiedEmail && typeof emailOnFile === "string" && emailOnFile && (
        <p className="ph-no-capture text-xs text-slate-500">
          {t("common.springboard_email_on_file", { email: emailOnFile })}
        </p>
      )}
    </div>
  );
};
