# AGENTS.md: warden-auth

Instructions for AI coding assistants adding authentication with this package
to an app or a backend, and for anyone changing the package itself.

## What it is

TypeScript SDK for Warden, a self-hosted auth service. Two entry points:

- `warden-auth`: client for browsers and React Native (`createWarden`).
- `warden-auth/server`: for backends (`createWardenServer`, `verifyWebhook`).

No runtime dependencies. Dual ESM/CJS build. Node.js 20+ on servers.

## Setting it up in a project

1. Ask the user for the Warden URL and a **publishable key** (`pk_...`, admin
   UI > API keys). Put them in public config (e.g. `VITE_WARDEN_URL`,
   `NEXT_PUBLIC_WARDEN_KEY`). For backends, a **secret key** (`sk_...`) goes in
   a server-only environment variable such as `WARDEN_SECRET_KEY`.
2. Create **one** client per app in its own module and import it everywhere:
   ```ts
   export const warden = createWarden({ url, publishableKey });
   ```
3. Call `await warden.restore()` once on app start, before deciding whether
   the user is signed in.
4. Render from `warden.onAuthStateChange()` / `warden.getSession()`; do not
   keep a second copy of the user or tokens in app state stores.
5. Call your own APIs with `warden.fetch(url, init)` (or put
   `await warden.getAccessToken()` in an `Authorization: Bearer` header).
6. In the API, protect routes with `warden.express({ roles: [...] })` or
   `await warden.verifyToken(token)` from `warden-auth/server`.

## Non-negotiable rules

- **Never** put a secret key (`sk_...`) in frontend or mobile code, in a
  `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` variable, or in a client bundle. The
  SDK throws if you try; do not work around it.
- Browsers: keep the default `mode: "cookie"`. Do not store tokens in
  `localStorage`, `sessionStorage` or cookies yourself.
- React Native: `mode: "token"` with a secure storage adapter
  (`expo-secure-store`, Keychain/Keystore). Never AsyncStorage for the refresh
  token.
- Do not call `/v1/auth/refresh` yourself and never refresh in parallel:
  Warden rotates refresh tokens and treats concurrent reuse as theft, which
  signs the user out. The client already refreshes once, ahead of expiry.
- Handle `signIn` results by `status`: `"authenticated"`, `"mfa_required"`
  (then `verifyMfa({ mfaToken, code })`) or `"verification_required"`.
- Branch on `err.code` from `WardenError`, never on `err.message` text.
- Roles: compare exact strings (`claims.roles.includes("admin")`). For
  payments, deletions and other sensitive actions use
  `express({ checkSession: true })` or `introspect()`: tokens keep old roles
  until they expire.
- Webhooks: verify with `verifyWebhook` on the **raw** body
  (`express.raw({ type: "application/json" })`), answer 2xx fast, deduplicate
  on `event.id`.
- Social sign-in redirect URIs must be listed exactly in Warden's allowed
  redirect URIs; web origins must be on the publishable key (CORS).
- Use Warden's JSON field names on user objects (`avatar_url`,
  `email_verified`, `mfa_enabled`, `locale`); do not invent camelCase copies.

## Common tasks

| Task | Code |
| --- | --- |
| Sign up with language | `warden.signUp({ email, password, name, locale: navigator.language })` |
| Update name or language | `warden.user.update({ name, locale })` |
| Profile photo | `warden.user.uploadAvatar(file)` |
| Devices | `warden.sessions.list()`, `.revoke(id)`, `.revokeOthers()` |
| Two-factor setup | `mfa.setupTotp()` (show `otpauth_url` as QR) then `mfa.enableTotp(code)` (show recovery codes once) |
| First admin user | server: `warden.users.create({ email, password, roles: ["admin"], emailVerified: true })` |
| Give a role | server: `warden.users.addRoles(userId, ["editor"])` |
| Protect a route | server: `app.get(path, warden.express({ roles: ["admin"] }), handler)` |

## Working on this repository

- `npm install --include=dev`, `npm run typecheck`, `npm test`, `npm run build`.
- No new runtime dependencies. Code must run in browsers, React Native,
  Node 20+, Deno, Bun and edge runtimes: use `fetch`, Web Crypto, `TextEncoder`;
  no Node built-ins in `src/`.
- Relative imports in `src/` end in `.js` (needed by the ESM build).
- Public API changes need README and this file updated, a CHANGELOG entry and
  a semver bump. Error codes are part of the API.
- `tests/e2e.mjs` runs the whole flow against a live Warden
  (`WARDEN_URL`, `WARDEN_SECRET_KEY`); run it before releases.
