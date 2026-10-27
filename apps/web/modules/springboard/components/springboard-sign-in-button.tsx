"use client";

import { useEffect, useRef, useState } from "react";
import { toast } from "react-hot-toast";
import { useTranslation } from "react-i18next";
import { authClient } from "@/modules/auth/lib/auth-client";
import { Button } from "@/modules/ui/components/button";

interface SpringboardSignInButtonProps {
  /** Where to land after a successful sign-in (already resolved and same-origin). */
  returnToUrl: string;
  /** Start the sign-in on mount, once (the login page decides when; see sso-redirect.ts). */
  autoStart?: boolean;
}

/**
 * "Sign in with Springboard". Rendered whenever the staff OIDC client is configured, independent of
 * any licence: it drives Better Auth's built-in social sign-in for the `springboard` provider.
 * A refusal comes back to `/auth/login?error=springboard_*`, which the login form explains.
 */
export const SpringboardSignInButton = ({
  returnToUrl,
  autoStart = false,
}: Readonly<SpringboardSignInButtonProps>) => {
  const { t } = useTranslation();
  const [isLoading, setIsLoading] = useState(false);
  const started = useRef(false);

  const handleSignIn = async () => {
    setIsLoading(true);
    try {
      const { error } = await authClient.signIn.social({
        provider: "springboard",
        callbackURL: returnToUrl,
        errorCallbackURL: "/auth/login",
      });
      if (error) {
        toast.error(error.message ?? t("common.something_went_wrong"));
        setIsLoading(false);
      }
    } catch {
      toast.error(t("common.something_went_wrong"));
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // A ref, not state: Strict Mode runs effects twice in development, and a second start would race.
    if (!autoStart || started.current) return;
    started.current = true;
    void handleSignIn();
    // handleSignIn is recreated each render; starting once on mount is the whole intent.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart]);

  return (
    <Button
      type="button"
      onClick={handleSignIn}
      loading={isLoading}
      className="h-11 w-full min-w-0 justify-center sm:h-9">
      <span className="truncate">{t("auth.login.continue_with_springboard")}</span>
    </Button>
  );
};
