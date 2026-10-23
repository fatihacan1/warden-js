<p align="center">
  <img src="https://raw.githubusercontent.com/fatihacan1/warden-js/main/docs/banner.png" alt="warden-auth: TypeScript SDK for Warden" width="100%" />
</p>

<h1 align="center">warden-auth</h1>

<p align="center">
  <strong>TypeScript SDK for <a href="https://github.com/fatihacan1/warden">Warden</a>, the self-hosted authentication service.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/warden-auth"><img src="https://img.shields.io/npm/v/warden-auth?color=cb3837&logo=npm&logoColor=white&label=npm" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/warden-auth"><img src="https://img.shields.io/npm/dm/warden-auth?color=333333&logo=npm" alt="npm downloads" /></a>
  <a href="https://github.com/fatihacan1/warden-js/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-Ready-3178c6?logo=typescript&logoColor=white" alt="TypeScript ready" /></a>
  <img src="https://img.shields.io/badge/dependencies-0-2ea44f" alt="Zero dependencies" />
  <a href="https://github.com/fatihacan1/warden-js/actions/workflows/ci.yml"><img src="https://github.com/fatihacan1/warden-js/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
</p>

---

- **Apps** (browser, React Native): sign-up, sign-in, two-factor, token refresh, profile and photo, devices, linked accounts, social sign-in with PKCE, native Apple and Google sign-in.
- **Backends** (Node.js 20+, Bun, Deno, edge): verify access tokens offline, check roles, Express middleware, create and manage users, verify webhooks.

Zero dependencies, ESM and CommonJS, fully typed. Ships an [`AGENTS.md`](AGENTS.md) so AI coding assistants use it the right way.

```bash
npm install warden-auth
```

<p align="center">
  <img src="https://raw.githubusercontent.com/fatihacan1/warden-js/main/docs/images/playground.png" alt="Playground: every SDK call behind a button, results in a live log" width="100%" />
  <br><sub>The <a href="examples/playground">playground</a>: every SDK call behind a button, against your own Warden.</sub>
</p>

## Contents

- [Quick start: web app](#quick-start-web-app)
- [Quick start: React Native](#quick-start-react-native)
- [Quick start: backend](#quick-start-backend)
- [Keys and security](#keys-and-security)
- [Client API](#client-api)
- [Server API](#server-api)
- [Service-to-service](#service-to-service)
- [Webhooks](#webhooks)
- [Errors](#errors)
- [Examples](#examples)
- [Using with brw-res-formatter](#using-with-brw-res-formatter)

## Quick start: web app

```ts
import { createWarden } from "warden-auth";

export const warden = createWarden({
  url: "https://auth.example.com",
  publishableKey: "pk_live_...", // admin UI > API keys
  // mode: "cookie" is the default in browsers: the refresh token lives in an
  // HttpOnly cookie, the access token only in memory.
});

// On app start: restore the session from the cookie.
await warden.restore();

// Sign in. Two-factor is a second step.
const res = await warden.signIn({ email, password });
if (res.status === "mfa_required") {
  await warden.verifyMfa({ mfaToken: res.mfaToken, code });
}

// React to sign-in, refresh, profile changes and sign-out.
warden.onAuthStateChange((state) => render(state?.user ?? null));

// Call your own API: the access token is attached and refreshed for you.
const orders = await warden.fetch("https://api.example.com/orders").then((r) => r.json());
```

Add your web app's origin to the publishable key (admin UI > API keys) so the browser may call Warden.

## Quick start: React Native

Use token mode and keep the refresh token in the platform's secure storage:

```ts
import * as SecureStore from "expo-secure-store";
import { createWarden } from "warden-auth";

export const warden = createWarden({
  url: "https://auth.example.com",
  publishableKey: "pk_live_...",
  mode: "token",
  storage: {
    getItem: (k) => SecureStore.getItemAsync(k),
    setItem: (k, v) => SecureStore.setItemAsync(k, v),
    removeItem: (k) => SecureStore.deleteItemAsync(k),
  },
});

await warden.restore(); // signed in again after an app restart
```

React Native needs `crypto.getRandomValues` (install `react-native-get-random-values`) and, for PKCE social sign-in, `crypto.subtle.digest` (for example `react-native-quick-crypto`). Native Apple and Google sign-in only need `getRandomValues`:

```ts
import { hashNonce } from "warden-auth";

const nonce = warden.oauth.createNonce();
const credential = await AppleAuthentication.signInAsync({ nonce: await hashNonce(nonce) });
await warden.oauth.signInWithIdToken("apple", { idToken: credential.identityToken!, nonce });
```

## Quick start: backend

```ts
import express from "express";
import { createWardenServer } from "warden-auth/server";

const warden = createWardenServer({
  url: "https://auth.example.com",
  audience: "warden",                         // TOKEN_AUDIENCE of your instance
  secretKey: process.env.WARDEN_SECRET_KEY,   // only for the server API
});

const app = express();

app.get("/me", warden.express(), (req, res) => res.json({ id: req.auth.userId }));
app.get("/admin", warden.express({ roles: ["admin"] }), (req, res) => res.json({ ok: true }));

// Create the first admin (works even when sign-ups are off).
await warden.users.create({ email: "ada@example.com", password: "…", roles: ["admin"], emailVerified: true });
```

`verifyToken()` checks the ES256 signature against Warden's JWKS (cached, refetched when Warden rotates keys), `typ: at+jwt`, issuer, audience, expiry and not-before. No call to Warden per request.

## Keys and security

| | Publishable key | Secret key |
| --- | --- | --- |
| Prefix | `pk_live_` / `pk_test_` | `sk_live_` / `sk_test_` |
| Where | `createWarden({ publishableKey })` in apps | `createWardenServer({ secretKey })` on servers |
| Sent as | `X-Warden-Key` | `Authorization: Bearer` |
| Secret? | No. It identifies the app; bind it to your web origins | Yes. Never ship it to a browser or a phone |

The SDK refuses a secret key in `createWarden` and a publishable key in `createWardenServer`. Warden itself rejects secret keys on requests that carry a browser `Origin` header.

What protects your users is not the publishable key but the protocol: short-lived ES256 access tokens, refresh tokens rotated on every use (reuse signs the session out), PKCE for social sign-in, HttpOnly cookies in browsers, secure storage on mobile, and exact CORS and redirect allowlists. This client implements the client side of all of it: one refresh at a time (parallel refreshes would look like token theft), refresh before expiry, retry once on `invalid_token`, state checks on OAuth redirects, nothing sensitive in `localStorage`.

## Client API

`createWarden(options)`

| Option | Default | |
| --- | --- | --- |
| `url` | required | Your Warden instance |
| `publishableKey` | | `pk_...` |
| `mode` | `"cookie"` in browsers, `"token"` elsewhere | Where the refresh token lives |
| `storage` | memory | Refresh token storage in token mode (secure storage on mobile) |
| `flowStorage` | `sessionStorage` in browsers | PKCE state during social sign-in |
| `refreshMarginSeconds` | `30` | Refresh this long before expiry |
| `fetch` | `globalThis.fetch` | Custom fetch |

| Method | Does |
| --- | --- |
| `restore()` | Restores the session on app start; `null` when signed out |
| `signUp({ email, password, name?, locale? })` | Creates an account |
| `signIn({ email, password })` | Signs in; may return `{ status: "mfa_required", mfaToken }` |
| `verifyMfa({ mfaToken, code })` | Second step with a TOTP or recovery code |
| `signOut()` | Signs this device out (local state cleared even offline) |
| `getSession()` | `{ user, accessToken, expiresAt, sessionId }` or `null`, synchronous |
| `onAuthStateChange(cb)` | Subscribe; returns an unsubscribe function |
| `getAccessToken()` | A fresh access token or `null` |
| `fetch(url, init)` | `fetch` with the access token, refresh and one retry on 401 |
| `providers()` | Sign-in methods enabled on the instance |
| `user.get()` / `user.update({ name?, locale? })` | Profile |
| `user.uploadAvatar(file)` / `user.deleteAvatar()` | Profile photo: `File`/`Blob`, bytes, or React Native `{ uri, name, type }` |
| `user.delete({ password? })` | Delete the account |
| `password.forgot(email)` / `password.reset({ token, password })` / `password.change({ currentPassword?, newPassword })` | Passwords |
| `email.verify(token)` / `email.resend()` | Email verification |
| `sessions.list()` / `sessions.revoke(id)` / `sessions.revokeOthers()` | Devices |
| `identities.list()` / `identities.unlink(provider)` | Linked social accounts |
| `mfa.setupTotp()` / `mfa.enableTotp(code)` / `mfa.disableTotp(code)` / `mfa.regenerateRecoveryCodes(code)` | Two-factor |
| `oauth.signInWithRedirect(provider, { redirectUri })` / `oauth.handleRedirect(url?)` | Social sign-in (browser) |
| `oauth.getAuthorizationUrl(provider, { redirectUri })` | Social sign-in URL for mobile in-app browsers |
| `oauth.signInWithIdToken(provider, { idToken, nonce, name? })` / `oauth.createNonce()` | Native Apple / Google |
| `graphql(query, variables?)` | When the instance has `GRAPHQL_ENABLED=true` |

User objects use Warden's JSON field names (`avatar_url`, `email_verified`, `mfa_enabled`, `locale`, ...).

## Server API

`createWardenServer({ url, secretKey?, issuer?, audience?, leewaySeconds?, jwksCacheSeconds?, fetch? })`

| Method | Does |
| --- | --- |
| `verifyToken(token)` | Offline verification; returns claims (`sub`, `sid`, `roles`, `email`, `amr`, ...) |
| `authenticate(req)` | `verifyToken` on the request's bearer token |
| `express({ roles?, allRoles?, scopes?, allowServiceTokens?, serviceOnly?, optional?, checkSession?, onError? })` | Middleware; sets `req.auth` (`userId`, `sessionId`, `roles`, `clientId`, `scopes`, ...). Service tokens need `scopes` (see below) |
| `introspect(token, { checkSession? })` | Online check: also revoked sessions, disabled users, current roles; for service tokens `client_id`, `scope` and whether the client is revoked |
| `serviceClient({ clientId, clientSecret, scope?, audience? })` | Tokens for calling other services (below), using this server's URL |
| `users.create(...)` / `users.get(id)` / `users.findByEmail(email)` | Users |
| `users.update(id, { name?, roles?, disabled?, locale? })` | Update; roles replace the list |
| `users.addRoles(id, roles)` / `users.removeRoles(id, roles)` | Role helpers |
| `users.revokeSessions(id)` | Sign out everywhere |
| `graphql(query, variables?)` | Server-side GraphQL with the secret key |
| `hasRole(claims, role)` | Exact role match |
| `isServiceToken(claims)` / `hasScope(claims, scope)` / `tokenScopes(claims)` | Tell service tokens from user tokens; exact scope match |

Roles are in the access token, so a role change shows up after the user's next refresh (within the access token lifetime). For sensitive actions use `checkSession: true` or `introspect`, which see changes immediately.

## Service-to-service

Microservices authenticate to each other with the OAuth 2.0 **client credentials** grant. Create a service client in Warden (admin UI, *Developers > Service clients*: name, allowed scopes and audiences), give its id (`svc_...`) and secret (`wcs_...`) to the calling service, and let the SDK fetch and cache short-lived tokens. The receiving service verifies them offline with the same JWKS as user tokens.

**Calling service.** The token is cached until 30 seconds before it expires, concurrent callers share one request, and a 401 from the receiver triggers one retry with a fresh token:

```ts
import { createServiceClient } from "warden-auth/server";

const billing = createServiceClient({
  url: "https://auth.example.com",
  clientId: process.env.WARDEN_CLIENT_ID!,
  clientSecret: process.env.WARDEN_CLIENT_SECRET!,   // from a secret manager, never in a client bundle
  audience: "billing-api",                           // the receiving service
  scope: "invoices:read",                            // optional: default is every scope the client may have
});

const res = await billing.fetch("https://billing.internal/invoices");
// or: const token = await billing.getToken();
```

`getServiceToken({ url, clientId, clientSecret, scope?, audience? })` is the one-call version with a process-wide cache, and `warden.serviceClient({ clientId, clientSecret })` reuses a `createWardenServer` instance's URL. `getToken({ scope, audience, forceRefresh })` can ask for other scopes or audiences than the defaults (each combination is cached separately). Errors are `WardenError`s with the OAuth code: `invalid_client`, `invalid_scope`, `invalid_target`, `rate_limited`, ...

**Receiving service.** Set `audience` to the name your service has in the client's allowed audiences, then require scopes:

```ts
import { createWardenServer, isServiceToken } from "warden-auth/server";

const warden = createWardenServer({ url: "https://auth.example.com", audience: "billing-api" });

// Users and services may both call this one; services must carry invoices:read.
app.get("/invoices", warden.express({ scopes: ["invoices:read"] }), (req, res) => {
  if (isServiceToken(req.auth)) console.log("called by", req.auth.clientId);
  res.json([]);
});

// Internal only: users are refused.
app.post("/internal/reindex", warden.express({ serviceOnly: true, scopes: ["invoices:write"] }), handler);
```

A route without `scopes`, `allowServiceTokens` or `serviceOnly` **refuses service tokens** with 403, so an endpoint written for signed-in users never runs for a machine by accident. For service tokens `roles` and `allRoles` do not apply (they have no roles) and `req.auth.userId` is empty; `req.auth.clientId` and `req.auth.scopes` are set. `verifyToken` accepts both kinds and gives `client_id` and `scope` on the claims; `checkSession: true` makes the middleware ask Warden whether the client is still active.

## Webhooks

```ts
import { verifyWebhook } from "warden-auth/server";

app.post("/webhooks/warden", express.raw({ type: "application/json" }), async (req, res) => {
  const event = await verifyWebhook({ secret: process.env.WARDEN_WEBHOOK_SECRET!, headers: req.headers, body: req.body });
  if (event.type === "user.created") { /* … */ }
  res.sendStatus(204);
});
```

Pass the **raw** body. Signatures follow [Standard Webhooks](https://www.standardwebhooks.com); requests older than 5 minutes are rejected. Deliveries are at-least-once: deduplicate on `event.id`.

## Errors

Every failure is a `WardenError` with a stable `code`, the HTTP `status`, a human `message`, optional `fields` (validation) and `requestId`.

```ts
import { isWardenError } from "warden-auth";

try {
  await warden.signIn({ email, password });
} catch (err) {
  if (isWardenError(err) && err.code === "invalid_credentials") showError("Wrong email or password");
  else if (isWardenError(err) && err.code === "rate_limited") showError(`Try again in ${err.retryAfter}s`);
  else throw err;
}
```

Network failures have `code: "network_error"` and `status: 0`.

## Examples

| Playground | Account screens |
| --- | --- |
| ![Playground](https://raw.githubusercontent.com/fatihacan1/warden-js/main/docs/images/playground.png) | ![Profile](https://raw.githubusercontent.com/fatihacan1/warden-js/main/docs/images/account-profile.png) |
| Every SDK call behind a button, with a live log | Sign-in, profile, photo, language, password, two-factor, linked accounts, devices |

![Security screen with two-factor setup](https://raw.githubusercontent.com/fatihacan1/warden-js/main/docs/images/account-security.png)

- [`examples/playground`](examples/playground): a test bench. Connect to your Warden, click through sign-up, sign-in, refresh (including five at once), profile, photo, devices and GraphQL, and see each request's result.

- [`examples/account-web`](examples/account-web): account screens with no framework: sign in and up, two-factor, profile and photo, email language, password, two-factor setup with recovery codes, linked accounts, devices. `npm run build && npm run example`, then open the printed URL.
- [`examples/express-api`](examples/express-api): an API with role checks, user management and a webhook receiver.

## Using with brw-res-formatter

The Express middleware takes an `onError` hook, so errors can use the same shape as the rest of your API:

```ts
import { sendErrorResponse } from "brw-res-formatter";

const auth = (opts = {}) =>
  warden.express({ ...opts, onError: (err, _req, res) => sendErrorResponse(res, err.status, err.message) });

app.get("/admin/reports", auth({ roles: ["admin"] }), handler);
// 401/403 answers: { "success": false, "status": 403, "message": "...", "data": null }
```

## License

[MIT](LICENSE)
