"use client";

import { useTranslation } from "react-i18next";
import { cn } from "@/lib/cn";

/** This fork's source, offered to every user and respondent (AGPL-3.0 section 13). */
export const SPRINGBOARD_SOURCE_URL = "https://github.com/Springboard-English/formbricks";

export const SourceCodeLink = ({ className }: Readonly<{ className?: string }>) => {
  const { t } = useTranslation();
  return (
    <a
      href={SPRINGBOARD_SOURCE_URL}
      target="_blank"
      rel="noopener noreferrer"
      className={cn("hover:underline", className)}>
      {t("common.source_code")}
    </a>
  );
};
