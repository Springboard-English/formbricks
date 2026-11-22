/**
 * `SPRINGBOARD_HYDRA_ONLY=1` (SPRINGBOARD.md, "Hydra is the only token issuer"): Formbricks stops being an
 * OAuth authorization server. Better Auth's `jwt()` and `oauthProvider()` plugins are not registered, and
 * every route that served them answers 404 here, before any handler runs. Pure, so it is unit-testable.
 *
 * Better Auth itself stays: it is the dashboard's session layer, and "Sign in with Springboard" is its
 * `genericOAuth` plugin, whose callback lives under `/api/auth/oauth2/callback/` and so stays open.
 */

const CLOSED_PREFIXES = [
  // Discovery for the OAuth server and the MCP resource.
  "/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration",
  "/.well-known/oauth-protected-resource",
  // The MCP server, which only accepts tokens this OAuth server minted.
  "/api/mcp",
  // The consent screen, and the "Authorized apps" settings page that lists and revokes its grants.
  "/account/authorize",
  "/account/settings/authorized-apps",
  // Better Auth's own copies: authorize, token, register (DCR), consent, userinfo, revoke, JWKS, admin.
  "/api/auth/oauth2/",
  "/api/auth/admin/oauth2/",
  "/api/auth/.well-known/",
  "/api/auth/jwks",
];

/** Staff sign-in's callback ("Sign in with Springboard" and upstream SSO alike). */
const OPEN_PREFIXES = ["/api/auth/oauth2/callback/"];

const startsWithSegment = (pathname: string, prefix: string): boolean =>
  prefix.endsWith("/")
    ? pathname.startsWith(prefix)
    : pathname === prefix || pathname.startsWith(`${prefix}/`);

/** True when the request is for part of the retired OAuth server. Case-insensitive, like the router. */
export const isClosedWhenHydraOnly = (pathname: string): boolean => {
  const path = pathname.toLowerCase();
  if (OPEN_PREFIXES.some((prefix) => path.startsWith(prefix))) return false;
  return CLOSED_PREFIXES.some((prefix) => startsWithSegment(path, prefix));
};
