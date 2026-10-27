# Springboard's fork of Formbricks

This repository is **Springboard's fork** of [formbricks/formbricks](https://github.com/formbricks/formbricks),
run at <https://forms.springboard.vn>. It is based on upstream tag `6.1.1` (`d5f5b7c2`); our changes live on
the `springboard/main` branch. The source of the running service is
<https://github.com/Springboard-English/formbricks>, linked as "Source code" from the login page and from the
footer of every link survey (AGPL-3.0 section 13).

Licensing is upstream's: the AGPL-3.0 core, and `apps/web/modules/ee/**` under the Formbricks Enterprise
licence. Every Springboard change is written in the AGPL core (mostly `apps/web/modules/springboard/**`). We
did not copy, adapt, edit or work around anything in `modules/ee`, and we do not unlock paid features: no
contacts, teams, roles, two-factor, workflows, dashboards, audit logs, quotas, AI, branding removal or higher
limits. Upstream's own SSO (Google, GitHub, Azure, OIDC, SAML) stays licence-gated exactly as upstream ships
it; "Sign in with Springboard" is a separate provider for Springboard's own identity service.

## What the fork changes

Each change is off until its environment variables are set, and is its own commit on `springboard/main`.

1. **Staff sign-in with Springboard OIDC.** A "Sign in with Springboard" button on the login page, against
   Springboard's Ory Hydra (STAFF client). Only verified staff addresses on an allowed domain get in; see the
   policy table below.
2. **Offboarding.** `POST /api/springboard/offboard` deactivates a user, revokes every session and removes
   their Springboard link; `GET /api/springboard/users` lists active users for daily reconciliation. Sessions
   last 12 hours by default.
3. **Identified respondents.** On link surveys, a per-survey switch "Sign in with Springboard to answer"
   (survey editor → Settings → Response options): respondents sign in with the separate RESPONDENT client.
   On in-app surveys, a respondent pass from Springboard's API. Either way the response carries the
   Springboard account key, account type and email on file. Core's "Anonymize responses" turns all of it off.
4. **Single workspace.** "Add new workspace" is hidden and creating a second workspace is refused on the
   server. This is not a licence limit and changes none.
5. **Source link, this file, and an image build** (`.github/workflows/springboard-image.yml`).

The MCP server at `/api/mcp` is untouched.

## Environment variables

| Variable                                 | Default          | Purpose                                                                                        |
| ---------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------- |
| `SPRINGBOARD_OIDC_ISSUER`                | unset (off)      | Hydra issuer. Prod `https://auth.springboard.vn`, dev `https://auth.springboard.vn/dev`.       |
| `SPRINGBOARD_OIDC_CLIENT_ID`             | unset (off)      | STAFF client id.                                                                               |
| `SPRINGBOARD_OIDC_CLIENT_SECRET`         | unset (off)      | STAFF client secret.                                                                           |
| `SPRINGBOARD_OIDC_ALLOWED_DOMAINS`       | `springboard.vn` | Comma list of email domains staff may sign in with (exact match, no subdomains).               |
| `SPRINGBOARD_OIDC_DEFAULT_ROLE`          | `member`         | Organization role for a new staff user without a pending invite.                               |
| `SPRINGBOARD_OIDC_STAFF_ACCOUNT_TYPES`   | unset            | Comma list of staff `account_type` values. **Required**: every sign-in is refused while unset. |
| `SPRINGBOARD_SESSION_HOURS`              | `12`             | Session lifetime. Only applies once Springboard sign-in is on, or when set explicitly.         |
| `SPRINGBOARD_OFFBOARD_SECRET`            | unset (off)      | Bearer secret for the offboarding endpoints, at least 32 characters. Same value on the API.    |
| `SPRINGBOARD_RESPONDENT_CLIENT_ID`       | unset (off)      | RESPONDENT client id. Must differ from the STAFF client.                                       |
| `SPRINGBOARD_RESPONDENT_CLIENT_SECRET`   | unset (off)      | RESPONDENT client secret.                                                                      |
| `SPRINGBOARD_RESPONDENT_COOKIE_SECRET`   | unset (off)      | Signs the respondent cookie, at least 32 characters.                                           |
| `SPRINGBOARD_RESPONDENT_PASS_PUBLIC_KEY` | unset (off)      | PEM public key of the API's JWT signing key; `\n` escapes allowed. Set with the issuer.        |
| `SPRINGBOARD_RESPONDENT_PASS_ISSUER`     | unset (off)      | The API's issuer, `https://api.springboard.vn`. The audience is this instance's `WEBAPP_URL`.  |
| `SPRINGBOARD_SINGLE_WORKSPACE`           | unset (off)      | `1` hides and blocks creating a second workspace.                                              |

The container refuses to start on a half-configured feature (for example an issuer without a client secret),
and logs a warning while `SPRINGBOARD_OIDC_STAFF_ACCOUNT_TYPES` is unset. Hydra clients must use
`token_endpoint_auth_method: client_secret_basic` and PKCE (S256). Redirect URIs to register:

- STAFF: `https://forms.springboard.vn/api/auth/oauth2/callback/springboard`
- RESPONDENT: `https://forms.springboard.vn/api/springboard/respondent/callback` (on `PUBLIC_URL` if one is set)

## Staff sign-in policy

The id_token is verified (signature against the issuer's JWKS, `iss`, `aud` = STAFF client, `exp`, and
Better Auth's nonce) before any of this runs. The rules are pure functions in
`apps/web/modules/springboard/lib/staff-policy.ts`, one unit test per row.

| Case                                                       | Outcome                                                                       |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------- |
| id_token carries only `sub` (today's Hydra)                | Refused, `springboard_missing_email`; no user created                         |
| `email_verified` is not exactly `true`                     | Refused, `springboard_email_unverified`                                       |
| Email domain not in `SPRINGBOARD_OIDC_ALLOWED_DOMAINS`     | Refused, `springboard_domain_not_allowed`                                     |
| `SPRINGBOARD_OIDC_STAFF_ACCOUNT_TYPES` unset               | Refused, `springboard_staff_types_unset`                                      |
| `account_type` missing or not a staff type                 | Refused, `springboard_not_staff`                                              |
| `sub` already linked, same address                         | Signed in as that user                                                        |
| `sub` already linked, IdP now reports another address      | Refused, `springboard_email_changed` (no silent move or rename)               |
| No link, a user has this address                           | Linked to that user (this provider only, verified address only)               |
| No link, that user already has a different Springboard sub | Refused, `springboard_account_conflict`                                       |
| Linked or matched user is inactive                         | Refused, `springboard_account_inactive`                                       |
| No user, pending invite for the address                    | Created, joins the invite's org with the invite's role; invite used           |
| No user, exactly one organization                          | Created, joins it with `SPRINGBOARD_OIDC_DEFAULT_ROLE`                        |
| No user, zero or several organizations                     | Refused, `springboard_no_organization` / `springboard_multiple_organizations` |

Upstream's global account linking stays off. New users are written like core invite acceptance: user,
account and membership in one Postgres transaction, then the membership projected to SpiceDB. They get
`identityProvider = openid`, which the core reads as "the identity provider owns this account": no password,
no password reset, no profile email/name edits. (No new enum value, so no migration.) Linked existing users
keep their `identityProvider`, and a password if they had one. Team assignments on invites are not applied
(teams are a paid feature).

## Offboarding and SSO-only login

`POST /api/springboard/offboard` with `Authorization: Bearer <SPRINGBOARD_OFFBOARD_SECRET>` and
`{"email": "..."}`:

- sets `User.isActive = false`, the core's own inactive flag, honoured by every sign-in path, every session
  read and the MCP server; re-projects the user's memberships to SpiceDB;
- revokes every session in Redis and in the database, and deletes the user's Springboard account link;
- keeps the user row, their surveys and their responses;
- answers `200 {"status":"ok"}` for an active user, an inactive one and an unknown address alike, `409` if the
  user is the last active owner of an organization, `401` without the secret, `429` when rate-limited, and
  `404` while the secret is unset.

`GET /api/springboard/users` returns `{"emails": [...]}`, active users only, behind the same secret.

**SSO-only (`EMAIL_AUTH_DISABLED=1`).** With the flag on, upstream switches Better Auth's email/password
endpoints off for _everyone_: there is no per-account exception, so a break-glass owner cannot sign in with a
password while it is set. We therefore recommend **leaving email auth on** and treating one owner account,
whose password lives in Secret Manager, as the only password account:

- Springboard-created staff accounts have no password and cannot get one (no reset for `openid` users).
- Existing users linked to Springboard keep any password they had; ask them not to use it, or remove it.
  Offboarding blocks them either way.
- If you do switch to `EMAIL_AUTH_DISABLED=1`, the break-glass procedure is: set it back to `0` on the VM and
  restart the container, sign in as the owner, fix things, set it to `1` again.

With Springboard sign-in configured and `EMAIL_AUTH_DISABLED=1`, the login page starts "Sign in with
Springboard" on arrival, so a person with a Hydra session lands straight in. It does not after a sign-out
(`/auth/login?signed_out=1`, which the core sign-out now goes to), or when the last sign-in was refused, so
neither loops. The rule is `apps/web/modules/springboard/lib/sso-redirect.ts`.

## Identified respondents

Respondents (students, parents, staff) are not Formbricks users: neither path creates a user, account or
session. **The identity is the Springboard account** (`sub`), proven by a signed token. The email is the
address on file: Springboard vouches for it (`email_verified: true`) only for staff mailboxes it created, so
for students and parents it is recorded as unverified, never refused.

**Link surveys: sign-in.** The respondent signs in on the RESPONDENT client (scopes `openid email profile`,
PKCE, state and nonce; the id_token is verified against the JWKS, `iss`, `aud`, `exp` and `nonce`). The
callback sets a two-hour signed HttpOnly, Secure, SameSite=Lax cookie bound to that one survey, and returns to
the survey with its original query string, so single-use links and hidden fields keep working.

**In-app surveys: a respondent pass.** The app (Leap) calls Springboard's
`POST /v2/users/me/respondent-pass` and sends the token as the embedded field `sb_pass`. The pass is RS256,
lives ten minutes, and must carry `typ: respondent_pass`, the configured issuer and this instance's
`WEBAPP_URL` as audience. **A survey that wants in-app answers identified declares an ingested embedded field
named `sb_pass`**, because the ingest contract keeps declared fields only. A missing or invalid pass saves the
answer without identity; it is never refused.

The response routes, not the page, are the trust boundary: on every create they read the cookie or the pass
and write `springboardAccountKey`, `springboardAccountType` and `springboardEmail` (plus core's
`verifiedEmail` when the address is vouched for), overwriting anything the client sent under those names, and
they always delete `sb_pass`. A survey requiring sign-in answers 403 without a valid cookie or pass. A partial
response can only be finished by the account that started it. No tokens are stored.

**Anonymous surveys.** Core's "Anonymize responses" toggle wins over everything above: no identity is
recorded, any embedded field ending in `_key`/`_id` (or named `email`) is dropped, and the page URL is cut to
its origin, because the app's URLs carry test and session ids. With sign-in also required, the sign-in then
only decides who may answer.

**Identified answers are not anonymous.** Survey owners should say so in the welcome card or first question
("Your Springboard account and email are recorded with your answers").

## Rebasing onto a new upstream tag

```shell
git fetch upstream --tags
git switch -c springboard/rebase-<new-tag> springboard/main
git rebase --onto <new-tag> 6.1.1        # replays the Springboard commits
pnpm install && pnpm build --filter=@formbricks/web^...
pnpm --dir apps/web exec vitest run modules/springboard
pnpm lint && pnpm typecheck && pnpm test
```

Then update the tag pattern in `.github/workflows/springboard-image.yml` and the base tag in this file, run
`pnpm i18n` for the new en-US strings, open a PR against `springboard/main`, and tag `<new-tag>-sb.1`.

Expect conflicts only in the upstream files we touch, almost all of them a few lines each:

- **Likely every release** (upstream edits these often): `apps/web/modules/auth/lib/auth.ts` (three lines:
  provider list, database hooks, session lifetime), `apps/web/lib/env.ts` and `apps/web/turbo.json` (one block
  each), `apps/web/locales/en-US.json`, `docker/docker-compose.yml`, the login form and page.
- **Sometimes**: the v1/v2 response routes and the shared PUT handler, `survey-renderer.tsx`,
  `legal-footer.tsx`, the survey editor's `page.tsx` / `survey-editor.tsx` / `settings-view.tsx` /
  `response-options-card.tsx`, the response card/table/export (`SingleResponseCardBody.tsx`,
  `VerifiedEmail.tsx`, `ResponseTableColumns.tsx`, `lib/response/{utils,service}.ts`),
  `link-settings-tab.tsx`, `createWorkspace` and the workspace switcher components, `route-config.ts`,
  `legacy-sso-callback.ts`, `oauth-error.ts`, `instrumentation.ts`, `scripts/docker/validate-env.ts`,
  `modules/auth/hooks/use-sign-out.ts` (the `signed_out` redirect) and its test.
- **Never**: everything under `modules/springboard/**`, `app/api/springboard/**`, this file and the workflow.

Watch Better Auth upgrades in particular: the staff flow relies on genericOAuth's `getUserInfo`,
`accountIssuer`, `disableSignUp` and pinned `redirectURI`, on the `/callback/:id` path, and on
`internalAdapter.deleteUserSessions`. The tests under `modules/springboard` fail loudly on most of those moves.
