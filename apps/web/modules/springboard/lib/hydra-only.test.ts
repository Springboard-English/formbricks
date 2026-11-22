import { describe, expect, test } from "vitest";
import { isClosedWhenHydraOnly } from "./hydra-only";

describe("isClosedWhenHydraOnly", () => {
  test.each([
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/api/auth",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource/api/mcp",
    "/api/mcp",
    "/API/MCP",
    "/account/authorize",
    "/account/settings/authorized-apps",
    "/api/auth/oauth2/authorize",
    "/api/auth/oauth2/token",
    "/api/auth/oauth2/register",
    "/api/auth/oauth2/consent",
    "/api/auth/admin/oauth2/create-client",
    "/api/auth/.well-known/openid-configuration",
    "/api/auth/jwks",
  ])("closes %s", (path) => {
    expect(isClosedWhenHydraOnly(path)).toBe(true);
  });

  test.each([
    "/api/auth/oauth2/callback/springboard",
    "/api/auth/callback/springboard",
    "/api/auth/sign-in/oauth2",
    "/api/auth/get-session",
    "/api/v3/surveys",
    "/api/mcpx",
    "/account/authorized",
    "/auth/login",
  ])("leaves %s open", (path) => {
    expect(isClosedWhenHydraOnly(path)).toBe(false);
  });
});
