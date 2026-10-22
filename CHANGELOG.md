# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
