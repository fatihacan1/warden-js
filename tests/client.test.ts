import { describe, expect, it, vi } from "vitest";
import { createWarden, memoryStorage, WardenError } from "../src/index";

type Call = { url: string; init: RequestInit };

function user(over: Record<string, unknown> = {}) {
  return { id: "u1", email: "ada@example.com", email_verified: true, name: "Ada", roles: [], mfa_enabled: false, has_password: true, created_at: "2026-01-01T00:00:00Z", ...over };
}

function tokens(n: number, ttlSeconds = 900) {
  return {
    access_token: "access-" + n,
    token_type: "Bearer",
    expires_in: ttlSeconds,
    expires_at: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
    refresh_token: "refresh-" + n,
    session_id: "s1",
  };
}

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

/** A fake Warden: routes are "METHOD /path" -> handler. */
function fakeServer(routes: Record<string, (call: Call) => Response | Promise<Response>>) {
  const calls: Call[] = [];
  const fetch = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    const call = { url, init };
    calls.push(call);
    const path = new URL(url).pathname;
    const h = routes[`${init.method ?? "GET"} ${path}`];
    return h ? h(call) : json(404, { error: { code: "not_found", message: "nope" } });
  });
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
}

const header = (c: Call, name: string) => new Headers(c.init.headers).get(name);

describe("token mode", () => {
  it("signs in, stores the refresh token and attaches the access token", async () => {
    const storage = memoryStorage();
    const srv = fakeServer({
      "POST /v1/auth/signin": () => json(200, { status: "authenticated", user: user(), tokens: tokens(1) }),
      "GET /v1/me": (c) => (header(c, "Authorization") === "Bearer access-1" ? json(200, user({ name: "Ada L." })) : json(401, {})),
    });
    const w = createWarden({ url: "https://auth.test/", publishableKey: "pk_test_x", mode: "token", storage, fetch: srv.fetch });
    const res = await w.signIn({ email: "ada@example.com", password: "pw" });
    expect(res.status).toBe("authenticated");
    expect(await storage.getItem("warden.refresh_token")).toBe("refresh-1");
    expect(header(srv.calls[0]!, "X-Warden-Key")).toBe("pk_test_x");
    expect(header(srv.calls[0]!, "X-Auth-Mode")).toBeNull();

    const me = await w.user.get();
    expect(me.name).toBe("Ada L.");
    expect(w.getSession()?.user.name).toBe("Ada L.");
  });

  it("refreshes once for concurrent callers and stores the rotated token", async () => {
    const storage = memoryStorage();
    await storage.setItem("warden.refresh_token", "refresh-0");
    let refreshes = 0;
    const srv = fakeServer({
      "POST /v1/auth/refresh": async (c) => {
        refreshes++;
        expect(JSON.parse(String(c.init.body))).toEqual({ refresh_token: "refresh-0" });
        await new Promise((r) => setTimeout(r, 10));
        return json(200, { status: "authenticated", user: user(), tokens: tokens(1) });
      },
    });
    const w = createWarden({ url: "https://auth.test", mode: "token", storage, fetch: srv.fetch });
    const all = await Promise.all([w.getAccessToken(), w.getAccessToken(), w.restore()]);
    expect(refreshes).toBe(1);
    expect(all[0]).toBe("access-1");
    expect(await storage.getItem("warden.refresh_token")).toBe("refresh-1");
  });

  it("refreshes an access token that is about to expire", async () => {
    let n = 0;
    const srv = fakeServer({
      "POST /v1/auth/signin": () => json(200, { status: "authenticated", user: user(), tokens: tokens(++n, 10) }),
      "POST /v1/auth/refresh": () => json(200, { status: "authenticated", user: user(), tokens: tokens(++n) }),
    });
    const w = createWarden({ url: "https://auth.test", mode: "token", fetch: srv.fetch });
    await w.signIn({ email: "a@b.co", password: "pw" });
    expect(await w.getAccessToken()).toBe("access-2"); // 10s left < 30s margin
  });

  it("retries once with a fresh token when the API says invalid_token", async () => {
    let n = 0;
    const srv = fakeServer({
      "POST /v1/auth/signin": () => json(200, { status: "authenticated", user: user(), tokens: tokens(++n) }),
      "POST /v1/auth/refresh": () => json(200, { status: "authenticated", user: user(), tokens: tokens(++n) }),
      "GET /v1/me/sessions": (c) =>
        header(c, "Authorization") === "Bearer access-2"
          ? json(200, { sessions: [{ id: "s1", current: true }] })
          : json(401, { error: { code: "invalid_token", message: "revoked" } }),
    });
    const w = createWarden({ url: "https://auth.test", mode: "token", fetch: srv.fetch });
    await w.signIn({ email: "a@b.co", password: "pw" });
    const list = await w.sessions.list();
    expect(list).toHaveLength(1);
  });

  it("signs out locally when the refresh token is rejected", async () => {
    const storage = memoryStorage();
    await storage.setItem("warden.refresh_token", "stolen");
    const srv = fakeServer({ "POST /v1/auth/refresh": () => json(401, { error: { code: "invalid_token", message: "x" } }) });
    const w = createWarden({ url: "https://auth.test", mode: "token", storage, fetch: srv.fetch });
    const states: unknown[] = [];
    w.onAuthStateChange((s) => states.push(s));
    expect(await w.restore()).toBeNull();
    expect(await storage.getItem("warden.refresh_token")).toBeNull();
    await expect(w.user.get()).rejects.toMatchObject({ code: "unauthorized" });
  });

  it("handles the MFA step", async () => {
    const srv = fakeServer({
      "POST /v1/auth/signin": () => json(200, { status: "mfa_required", mfa_token: "mfa-1" }),
      "POST /v1/auth/mfa/verify": (c) => {
        expect(JSON.parse(String(c.init.body))).toEqual({ mfa_token: "mfa-1", code: "123456" });
        return json(200, { status: "authenticated", user: user({ mfa_enabled: true }), tokens: tokens(1) });
      },
    });
    const w = createWarden({ url: "https://auth.test", mode: "token", fetch: srv.fetch });
    const first = await w.signIn({ email: "a@b.co", password: "pw" });
    expect(first).toEqual({ status: "mfa_required", mfaToken: "mfa-1", user: undefined });
    expect(w.getSession()).toBeNull();
    const second = await w.verifyMfa({ mfaToken: "mfa-1", code: "123456" });
    expect(second.status).toBe("authenticated");
  });

  it("turns error bodies into WardenError", async () => {
    const srv = fakeServer({
      "POST /v1/auth/signup": () =>
        json(422, { error: { code: "weak_password", message: "Too short.", fields: { password: "Too short." }, request_id: "r1" } }),
      "POST /v1/auth/signin": () => json(429, { error: { code: "rate_limited", message: "Slow down." } }, { "Retry-After": "7" }),
    });
    const w = createWarden({ url: "https://auth.test", mode: "token", fetch: srv.fetch });
    const err = await w.signUp({ email: "a@b.co", password: "x" }).catch((e) => e);
    expect(err).toBeInstanceOf(WardenError);
    expect(err).toMatchObject({ code: "weak_password", status: 422, fields: { password: "Too short." }, requestId: "r1" });
    expect(await w.signIn({ email: "a@b.co", password: "x" }).catch((e) => e)).toMatchObject({ code: "rate_limited", retryAfter: 7 });
  });

  it("reports network failures with a stable code", async () => {
    const w = createWarden({ url: "https://auth.test", mode: "token", fetch: (async () => { throw new TypeError("offline"); }) as typeof fetch });
    expect(await w.providers().catch((e) => e)).toMatchObject({ code: "network_error", status: 0 });
  });

  it("clears the session on sign-out even when offline", async () => {
    const storage = memoryStorage();
    let n = 0;
    const srv = fakeServer({ "POST /v1/auth/signin": () => json(200, { status: "authenticated", user: user(), tokens: tokens(++n) }) });
    const w = createWarden({ url: "https://auth.test", mode: "token", storage, fetch: srv.fetch });
    await w.signIn({ email: "a@b.co", password: "pw" });
    await w.signOut(); // signout route answers 404 here; local state must still go
    expect(w.getSession()).toBeNull();
    expect(await storage.getItem("warden.refresh_token")).toBeNull();
  });
});

describe("cookie mode", () => {
  it("sends X-Auth-Mode and credentials only on auth endpoints, and never stores the refresh token", async () => {
    const storage = memoryStorage();
    const t = { ...tokens(1), refresh_token: undefined };
    const srv = fakeServer({
      "POST /v1/auth/signin": () => json(200, { status: "authenticated", user: user(), tokens: t }),
      "PATCH /v1/me": () => json(200, user({ name: "New" })),
    });
    const w = createWarden({ url: "https://auth.test", mode: "cookie", storage, fetch: srv.fetch });
    await w.signIn({ email: "a@b.co", password: "pw" });
    expect(header(srv.calls[0]!, "X-Auth-Mode")).toBe("cookie");
    expect(srv.calls[0]!.init.credentials).toBe("include");
    await w.user.update({ name: "New" });
    expect(srv.calls[1]!.init.credentials).toBe("omit");
    expect(await storage.getItem("warden.refresh_token")).toBeNull();
  });
});

describe("safety", () => {
  it("refuses a secret key in an app", () => {
    expect(() => createWarden({ url: "https://auth.test", publishableKey: "sk_live_abc" })).toThrow(/secret key/);
  });
});

describe("social sign-in", () => {
  it("builds a PKCE authorize URL and rejects a redirect with the wrong state", async () => {
    const flow = memoryStorage();
    const srv = fakeServer({
      "POST /v1/oauth/token": (c) => {
        const b = JSON.parse(String(c.init.body));
        expect(b.code).toBe("code-1");
        expect(b.code_verifier.length).toBeGreaterThanOrEqual(43);
        expect(b.redirect_uri).toBe("myapp://auth/callback");
        return json(200, { status: "authenticated", user: user(), tokens: tokens(1), new_user: true });
      },
    });
    const w = createWarden({ url: "https://auth.test", publishableKey: "pk_test_x", mode: "token", flowStorage: flow, fetch: srv.fetch });
    const url = new URL(await w.oauth.getAuthorizationUrl("google", { redirectUri: "myapp://auth/callback" }));
    expect(url.pathname).toBe("/v1/oauth/google/authorize");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("client_key")).toBe("pk_test_x");
    const state = url.searchParams.get("state")!;

    await expect(w.oauth.handleRedirect(`myapp://auth/callback?code=code-1&state=forged`)).rejects.toMatchObject({ code: "invalid_token" });
    // The flow is single use: even the right state fails after a failed attempt.
    await expect(w.oauth.handleRedirect(`myapp://auth/callback?code=code-1&state=${state}`)).rejects.toMatchObject({ code: "invalid_token" });

    const url2 = new URL(await w.oauth.getAuthorizationUrl("google", { redirectUri: "myapp://auth/callback" }));
    const res = await w.oauth.handleRedirect(`myapp://auth/callback?code=code-1&state=${url2.searchParams.get("state")}`);
    expect(res).toMatchObject({ status: "authenticated", newUser: true });
  });
});

describe("avatar upload", () => {
  it("sends a Blob as multipart field file", async () => {
    let n = 0;
    const srv = fakeServer({
      "POST /v1/auth/signin": () => json(200, { status: "authenticated", user: user(), tokens: tokens(++n) }),
      "PUT /v1/me/avatar": (c) => {
        expect(c.init.body).toBeInstanceOf(FormData);
        expect((c.init.body as FormData).get("file")).toBeInstanceOf(Blob);
        return json(200, user({ avatar_url: "https://cdn.test/a.jpg" }));
      },
    });
    const w = createWarden({ url: "https://auth.test", mode: "token", fetch: srv.fetch });
    await w.signIn({ email: "a@b.co", password: "pw" });
    const u = await w.user.uploadAvatar(new Blob([new Uint8Array([1, 2, 3])], { type: "image/png" }));
    expect(u.avatar_url).toBe("https://cdn.test/a.jpg");
    expect(w.getSession()?.user.avatar_url).toBe("https://cdn.test/a.jpg");
  });
});
