import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { createServiceClient, createWardenServer, getServiceToken, hasScope, isServiceToken, WardenError } from "../src/server";

const subtle = webcrypto.subtle;
const b64url = (b: Uint8Array | ArrayBuffer) => Buffer.from(b instanceof ArrayBuffer ? new Uint8Array(b) : b).toString("base64url");

async function keypair(kid: string) {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  return { kid, privateKey: pair.privateKey, jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid, alg: "ES256", use: "sig" } };
}

async function sign(key: CryptoKey, header: Record<string, unknown>, claims: Record<string, unknown>) {
  const h = b64url(Buffer.from(JSON.stringify(header)));
  const p = b64url(Buffer.from(JSON.stringify(claims)));
  const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}

const now = () => Math.floor(Date.now() / 1000);
const serviceClaims = (over: Record<string, unknown> = {}) => ({
  iss: "https://auth.test",
  sub: "client:svc_abc",
  client_id: "svc_abc",
  scope: "orders:read orders:write",
  aud: ["orders-api"],
  exp: now() + 600,
  iat: now(),
  jti: "j1",
  ...over,
});

async function setup() {
  const k = await keypair("k1");
  const fetch = vi.fn(async () => new Response(JSON.stringify({ keys: [k.jwk] }), { status: 200 }));
  const server = createWardenServer({
    url: "https://auth.test",
    audience: "orders-api",
    secretKey: "sk_test_abc",
    fetch: fetch as unknown as typeof globalThis.fetch,
  });
  const token = (claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}) =>
    sign(k.privateKey, { alg: "ES256", typ: "at+jwt", kid: "k1", ...header }, serviceClaims(claims));
  const userToken = () =>
    sign(
      k.privateKey,
      { alg: "ES256", typ: "at+jwt", kid: "k1" },
      { iss: "https://auth.test", sub: "u1", sid: "s1", aud: ["orders-api"], exp: now() + 600, iat: now(), roles: ["admin"], amr: ["pwd"], email_verified: true },
    );
  return { server, token, userToken };
}

describe("verifyToken with service tokens", () => {
  it("accepts a service token and exposes client_id and scope", async () => {
    const { server, token } = await setup();
    const c = await server.verifyToken(await token());
    expect(isServiceToken(c)).toBe(true);
    expect(c).toMatchObject({ sub: "client:svc_abc", client_id: "svc_abc", scope: "orders:read orders:write", sid: "", roles: [] });
    expect(hasScope(c, "orders:read")).toBe(true);
    expect(hasScope(c, "orders")).toBe(false);
  });

  it("does not mistake user tokens for service tokens", async () => {
    const { server, userToken } = await setup();
    const c = await server.verifyToken(await userToken());
    expect(isServiceToken(c)).toBe(false);
    expect(hasScope(c, "orders:read")).toBe(false);
  });

  it.each([
    ["sub that does not match the client", { sub: "client:svc_other" }],
    ["a user id as subject", { sub: "u1" }],
    ["a session", { sid: "s1" }],
    ["another audience", { aud: ["billing-api"] }],
    ["expired", { exp: now() - 3600 }],
  ])("rejects a service token with %s", async (_n, over) => {
    const { server, token } = await setup();
    await expect(server.verifyToken(await token(over))).rejects.toMatchObject({ code: "invalid_token", status: 401 });
  });
});

describe("express middleware and service tokens", () => {
  type Mw = ReturnType<ReturnType<typeof createWardenServer>["express"]>;
  function run(mw: Mw, auth: string) {
    return new Promise<{ status?: number; body?: unknown; req: { auth?: Record<string, unknown> }; nextCalled: boolean }>((resolve) => {
      const req = { headers: { authorization: auth } } as { headers: Record<string, string>; auth?: Record<string, unknown> };
      const out: { status?: number; body?: unknown; req: typeof req; nextCalled: boolean } = { req, nextCalled: false };
      const res = {
        setHeader() {},
        status(code: number) {
          out.status = code;
          return { json: (b: unknown) => { out.body = b; resolve(out); } };
        },
      };
      mw(req, res, () => {
        out.nextCalled = true;
        resolve(out);
      });
    });
  }

  it("refuses service tokens on routes that did not opt in", async () => {
    const { server, token } = await setup();
    const r = await run(server.express(), "Bearer " + (await token()));
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: { code: "forbidden" } });
    expect((await run(server.express({ roles: ["admin"] }), "Bearer " + (await token()))).status).toBe(403);
  });

  it("requires every listed scope", async () => {
    const { server, token } = await setup();
    const ok = await run(server.express({ scopes: ["orders:read"] }), "Bearer " + (await token()));
    expect(ok.nextCalled).toBe(true);
    expect(ok.req.auth).toMatchObject({ clientId: "svc_abc", userId: "", sessionId: "", scopes: ["orders:read", "orders:write"] });
    const both = await run(server.express({ scopes: ["orders:read", "orders:write"] }), "Bearer " + (await token()));
    expect(both.nextCalled).toBe(true);
    const missing = await run(server.express({ scopes: ["orders:read", "orders:delete"] }), "Bearer " + (await token()));
    expect(missing.status).toBe(403);
    const none = await run(server.express({ scopes: ["orders:read"] }), "Bearer " + (await token({ scope: "" })));
    expect(none.status).toBe(403);
  });

  it("lets users through scopes routes and keeps role checks for them", async () => {
    const { server, userToken } = await setup();
    const u = await run(server.express({ scopes: ["orders:read"], roles: ["admin"] }), "Bearer " + (await userToken()));
    expect(u.nextCalled).toBe(true);
    expect(u.req.auth).toMatchObject({ userId: "u1", scopes: [] });
    expect((await run(server.express({ scopes: ["orders:read"], roles: ["billing"] }), "Bearer " + (await userToken()))).status).toBe(403);
  });

  it("serviceOnly refuses users", async () => {
    const { server, token, userToken } = await setup();
    expect((await run(server.express({ serviceOnly: true }), "Bearer " + (await token()))).nextCalled).toBe(true);
    expect((await run(server.express({ serviceOnly: true }), "Bearer " + (await userToken()))).status).toBe(403);
    expect((await run(server.express({ allowServiceTokens: true }), "Bearer " + (await token()))).nextCalled).toBe(true);
  });
});

describe("service client", () => {
  beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
  afterEach(() => vi.useRealTimers());

  const tokenResponse = (n: number, expiresIn = 900) =>
    new Response(JSON.stringify({ access_token: `tok${n}`, token_type: "Bearer", expires_in: expiresIn, scope: "orders:read" }), { status: 200 });

  function mock(expiresIn = 900) {
    let n = 0;
    const calls: { url: string; init: RequestInit }[] = [];
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      if (String(input).endsWith("/v1/oauth/token")) {
        await Promise.resolve();
        return tokenResponse(++n, expiresIn);
      }
      return new Response("ok", { status: 200 });
    });
    return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
  }

  const base = { url: "https://auth.test", clientId: "svc_abc", clientSecret: "wcs_secret" };

  it("asks with HTTP Basic and a form body", async () => {
    const { fetch, calls } = mock();
    const c = createServiceClient({ ...base, scope: ["orders:read", "orders:write"], audience: "orders-api", fetch });
    expect(await c.getToken()).toBe("tok1");
    const { init } = calls[0]!;
    expect(new Headers(init.headers).get("Authorization")).toBe("Basic " + Buffer.from("svc_abc:wcs_secret").toString("base64"));
    expect(new Headers(init.headers).get("Content-Type")).toBe("application/x-www-form-urlencoded");
    const body = new URLSearchParams(String(init.body));
    expect(body.get("grant_type")).toBe("client_credentials");
    expect(body.get("scope")).toBe("orders:read orders:write");
    expect(body.get("audience")).toBe("orders-api");
    expect(body.get("client_secret")).toBeNull();
  });

  it("can send the credentials in the body", async () => {
    const { fetch, calls } = mock();
    await createServiceClient({ ...base, authMethod: "post", fetch }).getToken();
    const body = new URLSearchParams(String(calls[0]!.init.body));
    expect(body.get("client_id")).toBe("svc_abc");
    expect(body.get("client_secret")).toBe("wcs_secret");
    expect(new Headers(calls[0]!.init.headers).get("Authorization")).toBeNull();
  });

  it("caches until shortly before expiry, then renews", async () => {
    const { fetch } = mock(900);
    const c = createServiceClient({ ...base, fetch });
    expect(await c.getToken()).toBe("tok1");
    vi.setSystemTime(Date.now() + 800_000);
    expect(await c.getToken()).toBe("tok1");
    expect(fetch).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + 80_000); // 880s: inside the 30s renewal window
    expect(await c.getToken()).toBe("tok2");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("caps the renewal window at half of a short lifetime", async () => {
    const { fetch } = mock(40);
    const c = createServiceClient({ ...base, fetch });
    await c.getToken();
    vi.setSystemTime(Date.now() + 15_000);
    await c.getToken();
    expect(fetch).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + 6_000);
    await c.getToken();
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("shares one request between concurrent callers", async () => {
    const { fetch } = mock();
    const c = createServiceClient({ ...base, fetch });
    const all = await Promise.all(Array.from({ length: 25 }, () => c.getToken()));
    expect(new Set(all)).toEqual(new Set(["tok1"]));
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("keeps separate tokens per scope and audience", async () => {
    const { fetch } = mock();
    const c = createServiceClient({ ...base, fetch });
    const [a, b, a2] = await Promise.all([c.getToken({ scope: "a" }), c.getToken({ scope: "b" }), c.getToken({ scope: "a" })]);
    expect(a).toBe(a2);
    expect(a).not.toBe(b);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("does not cache failures and maps OAuth errors", async () => {
    const answers = [
      new Response(JSON.stringify({ error: "invalid_client", error_description: "Client authentication failed." }), { status: 401 }),
      new Response(JSON.stringify({ error: { code: "rate_limited", message: "Slow down." } }), { status: 429, headers: { "Retry-After": "7" } }),
      tokenResponse(1),
    ];
    const fetch = vi.fn(async () => answers.shift()!) as unknown as typeof globalThis.fetch;
    const c = createServiceClient({ ...base, fetch });
    await expect(c.getToken()).rejects.toMatchObject({ code: "invalid_client", status: 401, message: "Client authentication failed." });
    await expect(c.getToken()).rejects.toMatchObject({ code: "rate_limited", status: 429, retryAfter: 7 });
    expect(await c.getToken()).toBe("tok1");
  });

  it("reports network failures and bad responses", async () => {
    const down = createServiceClient({ ...base, fetch: (async () => { throw new TypeError("x"); }) as unknown as typeof globalThis.fetch });
    await expect(down.getToken()).rejects.toMatchObject({ code: "network_error" });
    const odd = createServiceClient({ ...base, fetch: (async () => new Response("{}", { status: 200 })) as unknown as typeof globalThis.fetch });
    await expect(odd.getToken()).rejects.toBeInstanceOf(WardenError);
  });

  it("fetch adds the bearer token and retries once on 401", async () => {
    let tokenCalls = 0;
    let apiCalls = 0;
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/v1/oauth/token")) return tokenResponse(++tokenCalls);
      apiCalls++;
      const auth = new Headers(init?.headers).get("Authorization");
      return new Response("x", { status: auth === "Bearer tok2" ? 200 : 401 });
    }) as unknown as typeof globalThis.fetch;
    const c = createServiceClient({ ...base, fetch });
    const res = await c.fetch("https://orders.internal/orders", { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } });
    expect(res.status).toBe(200);
    expect(tokenCalls).toBe(2);
    expect(apiCalls).toBe(2);
  });

  it("getServiceToken shares a client per configuration", async () => {
    const { fetch } = mock();
    const opts = { ...base, clientId: "svc_shared", fetch };
    expect(await getServiceToken(opts)).toBe("tok1");
    expect(await getServiceToken(opts)).toBe("tok1");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(await getServiceToken({ ...opts, forceRefresh: true })).toBe("tok2");
  });

  it("refuses API keys and missing credentials", () => {
    expect(() => createServiceClient({ ...base, clientId: "sk_live_x" })).toThrow(/service client/);
    expect(() => createServiceClient({ url: "https://auth.test", clientId: "", clientSecret: "" })).toThrow();
  });

  it("WardenServer.serviceClient uses the server's URL", async () => {
    const { fetch, calls } = mock();
    const server = createWardenServer({ url: "https://auth.test/", fetch });
    await server.serviceClient({ clientId: "svc_abc", clientSecret: "wcs_x" }).getToken();
    expect(calls[0]!.url).toBe("https://auth.test/v1/oauth/token");
  });
});
