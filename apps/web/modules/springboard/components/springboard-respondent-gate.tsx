"use client";

import { LogInIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { TUserLocale } from "@formbricks/types/user";
import { useAppLocale } from "@/modules/survey/link/hooks/use-app-locale";
import { Button } from "@/modules/ui/components/button";
import { SourceCodeLink } from "./source-code-link";

interface SpringboardRespondentGateProps {
  /** `/api/springboard/respondent/start?…`, or `null` when the instance cannot sign anyone in. */
  startUrl: string | null;
  /** A `springboardError` code the callback came back with, if any. */
  error?: string;
  locale: TUserLocale;
}

/** Shown on a link survey that requires "Sign in with Springboard" until the respondent has done so. */
export const SpringboardRespondentGate = ({
  startUrl,
  error,
  locale,
}: Readonly<SpringboardRespondentGateProps>) => {
  const { t } = useTranslation();
  const isLocaleReady = useAppLocale(locale);
  if (!isLocaleReady) return null;

  return (
    <div className="flex min-h-screen w-full flex-col items-center justify-center bg-slate-50 px-4">
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-8 text-center shadow-sm">
        <div className="mx-auto mb-4 flex size-14 items-center justify-center rounded-full bg-slate-100">
          <LogInIcon className="size-6 text-slate-600" strokeWidth={1.5} />
        </div>
        <h1 className="text-lg font-semibold text-slate-800">{t("s.springboard_sign_in_to_continue")}</h1>
        <p className="mt-2 text-sm text-slate-600">{t("s.springboard_sign_in_description")}</p>
        {error && (
          <p role="alert" className="mt-4 rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
            {t("s.springboard_sign_in_failed", { code: error })}
          </p>
        )}
        {startUrl ? (
          <Button asChild className="mt-6 w-full">
            <a href={startUrl}>{t("auth.login.continue_with_springboard")}</a>
          </Button>
        ) : (
          <p className="mt-6 text-sm text-slate-500">{t("s.springboard_sign_in_unavailable")}</p>
        )}
      </div>
      <footer className="mt-6 text-xs text-slate-500">
        <SourceCodeLink />
      </footer>
    </div>
  );
};
