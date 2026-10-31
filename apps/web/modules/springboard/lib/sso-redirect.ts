/**
 * When the login page sends the browser straight on to "Sign in with Springboard".
 *
 * Only once Springboard is the sole way in (staff client configured AND `EMAIL_AUTH_DISABLED=1`),
 * and never right after a sign-out or a refused sign-in: the Hydra session outlives Formbricks', so
 * redirecting then would sign the person straight back in, or loop on the refusal. Client-safe.
 */

export const SPRINGBOARD_SIGNED_OUT_PARAM = "signed_out";

export const shouldAutoStartSpringboardSignIn = ({
  springboardSignInEnabled,
  emailAuthEnabled,
  oauthError,
  signedOut,
}: {
  springboardSignInEnabled: boolean;
  emailAuthEnabled: boolean;
  oauthError: string | undefined | null;
  signedOut: string | undefined | null;
}): boolean => springboardSignInEnabled && !emailAuthEnabled && !oauthError && signedOut !== "1";
