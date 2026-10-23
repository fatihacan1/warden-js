# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

Requires a Warden version with service clients (OAuth 2.0 client credentials).

### Added
- Service-to-service authentication in `warden-auth/server`:
  `createServiceClient`, `getServiceToken` and `warden.serviceClient()` get
  access tokens with the client credentials grant, cache them until shortly
  before they expire (never past half of a short lifetime), share one request
  between concurrent callers, and retry once on a 401 from the receiver
  (`client.fetch`). Both HTTP Basic and body credentials are supported.
- `verifyToken` accepts service tokens and exposes `client_id` and `scope` on
  the claims. New helpers `isServiceToken`, `hasScope`, `tokenScopes`.
- Express middleware options `scopes`, `allowServiceTokens` and `serviceOnly`;
  `req.auth` gains `clientId` and `scopes`.
- `introspect` returns `client_id`, `scope`, `aud` and `token_type: "service"`
  for service tokens, and `reason: "client_revoked"`.

### Changed
- The middleware refuses service tokens with 403 `forbidden` unless the route
  opts in with `scopes`, `allowServiceTokens` or `serviceOnly`, so existing
  user-only routes cannot be reached by a machine. `roles` and `allRoles`
  apply to users only.
- `req.auth` now always has a `scopes` array (empty for users).

## [0.1.0] - 2026-10-22

### Added
- `createWarden` client: sign-up, sign-in, two-factor, single-flight token
  refresh, cookie mode for browsers and token mode with pluggable secure
  storage for React Native, authorized `fetch`, profile, photo upload, email
  language, passwords, email verification, devices, linked accounts,
  two-factor management, PKCE social sign-in, native Apple/Google sign-in,
  GraphQL.
- `warden-auth/server`: offline ES256 token verification with a cached JWKS,
  Express middleware with role checks, token introspection, user management
  with secret keys, `verifyWebhook` (Standard Webhooks).
- `WardenError` with stable codes.
- Example account screens and an Express API example.
- `AGENTS.md` and `llms.txt` for AI coding assistants.
