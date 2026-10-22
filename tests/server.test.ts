import { describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { createWardenServer, hasRole, verifyWebhook, WardenError } from "../src/server";

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
const baseClaims = () => ({ iss: "https://auth.test", sub: "u1", sid: "s1", aud: ["warden"], exp: now() + 600, iat: now(), roles: ["admin"], amr: ["pwd"], email_verified: true });

async function setup() {
  const k = await keypair("k1");
  const fetch = vi.fn(async () => new Response(JSON.stringify({ keys: [k.jwk] }), { status: 200 }));
  const server = createWardenServer({ url: "https://auth.test", fetch: fetch as unknown as typeof globalThis.fetch });
  const token = (over: Record<string, unknown> = {}, header: Record<string, unknown> = {}) =>
    sign(k.privateKey, { alg: "ES256", typ: "at+jwt", kid: "k1", ...header }, { ...baseClaims(), ...over });
  return { server, token, fetch, k };
}

describe("verifyToken", () => {
  it("accepts a valid token and caches the keys", async () => {
    const { server, token, fetch } = await setup();
    const c = await server.verifyToken(await token());
    expect(c.sub).toBe("u1");
    expect(hasRole(c, "admin")).toBe(true);
    expect(hasRole(c, "adm")).toBe(false);
    await server.verifyToken(await token());
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["expired", { exp: now() - 3600 }, {}],
    ["wrong issuer", { iss: "https://evil.test" }, {}],
    ["wrong audience", { aud: ["other-api"] }, {}],
    ["not yet valid", { nbf: now() + 3600 }, {}],
    ["ID token type", {}, { typ: "JWT" }],
    ["unknown key", {}, { kid: "nope" }],
  ])("rejects %s", async (_name, claims, header) => {
    const { server, token } = await setup();
    await expect(server.verifyToken(await token(claims, header))).rejects.toMatchObject({ code: "invalid_token", status: 401 });
  });

  it("rejects alg=none and tampered payloads", async () => {
    const { server, token } = await setup();
    const t = await token();
    const [h, p, s] = t.split(".");
    const none = b64url(Buffer.from(JSON.stringify({ alg: "none", typ: "at+jwt", kid: "k1" }))) + "." + p + ".";
    await expect(server.verifyToken(none)).rejects.toBeInstanceOf(WardenError);
    const forged = b64url(Buffer.from(JSON.stringify({ ...baseClaims(), roles: ["admin", "owner"] })));
    await expect(server.verifyToken(`${h}.${forged}.${s}`)).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("rejects tokens signed by a key that is not in the JWKS", async () => {
    const { server } = await setup();
    const other = await keypair("k1"); // same kid, different key
    const t = await sign(other.privateKey, { alg: "ES256", typ: "at+jwt", kid: "k1" }, baseClaims());
    await expect(server.verifyToken(t)).rejects.toMatchObject({ code: "invalid_token" });
  });
});

describe("express middleware", () => {
  function run(mw: ReturnType<ReturnType<typeof createWardenServer>["express"]>, auth?: string) {
    return new Promise<{ status?: number; body?: unknown; req: { auth?: { userId: string } }; nextCalled: boolean }>((resolve) => {
      const req = { headers: auth ? { authorization: auth } : {} } as { headers: Record<string, string>; auth?: { userId: string } };
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

  it("sets req.auth and enforces roles", async () => {
    const { server, token } = await setup();
    const ok = await run(server.express({ roles: ["admin"] }), "Bearer " + (await token()));
    expect(ok.nextCalled).toBe(true);
    expect(ok.req.auth?.userId).toBe("u1");

    const denied = await run(server.express({ roles: ["billing"] }), "Bearer " + (await token()));
    expect(denied.status).toBe(403);
    expect(denied.body).toMatchObject({ error: { code: "forbidden" } });

    expect((await run(server.express())).status).toBe(401);
    expect((await run(server.express({ optional: true }))).nextCalled).toBe(true);
  });
});

describe("server API", () => {
  it("sends the secret key and maps errors", async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer sk_test_abc");
      if (String(input).endsWith("/v1/server/users?email=ghost%40example.com")) {
        return new Response(JSON.stringify({ error: { code: "not_found", message: "x" } }), { status: 404 });
      }
      return new Response(JSON.stringify({ id: "u1", roles: ["admin"], ...JSON.parse(String(init?.body ?? "{}")) }), { status: 201 });
    });
    const server = createWardenServer({ url: "https://auth.test", secretKey: "sk_test_abc", fetch: fetch as unknown as typeof globalThis.fetch });
    const u = await server.users.create({ email: "ada@example.com", roles: ["admin"], emailVerified: true });
    expect(u).toMatchObject({ id: "u1", email: "ada@example.com", email_verified: true });
    expect(await server.users.findByEmail("ghost@example.com")).toBeNull();
  });

  it("refuses a publishable key as secret key", () => {
    expect(() => createWardenServer({ url: "https://auth.test", secretKey: "pk_live_x" })).toThrow(/secret key/);
  });
});

describe("verifyWebhook", () => {
  // Test vector from the Standard Webhooks specification.
  const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
  const headers = {
    "webhook-id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
    "webhook-timestamp": "1614265330",
    "webhook-signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
  };
  const body = '{"test": 2432232314}';
  const at = () => 1614265330 * 1000 + 60_000;

  it("accepts the reference signature", async () => {
    await expect(verifyWebhook({ secret, headers, body, now: at })).resolves.toEqual({ test: 2432232314 });
    await expect(verifyWebhook({ secret, headers: new Headers(headers), body: Buffer.from(body), now: at })).resolves.toBeTruthy();
  });

  it("rejects modified bodies, old timestamps and missing headers", async () => {
    await expect(verifyWebhook({ secret, headers, body: body + " ", now: at })).rejects.toMatchObject({ code: "invalid_signature" });
    await expect(verifyWebhook({ secret, headers, body, now: () => at() + 3600_000 })).rejects.toMatchObject({ code: "invalid_signature" });
    await expect(verifyWebhook({ secret, headers: {}, body, now: at })).rejects.toMatchObject({ code: "invalid_signature" });
  });
});
