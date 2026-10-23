import { WardenError } from "./errors.js";
import { base64Encode, utf8 } from "./encoding.js";

export interface ServiceClientOptions {
  /** Base URL of your Warden instance. */
  url: string;
  /** Client id of the service client (`svc_...`), from the admin UI > Service clients. */
  clientId: string;
  /** Client secret (`wcs_...`). Keep it in your secret manager; never ship it to a browser or a phone. */
  clientSecret: string;
  /** Default scopes (space separated or a list). Omitted: all scopes the client is allowed. */
  scope?: string | string[];
  /** Default audience: the service that will receive the token. Omitted: the client's first allowed audience. */
  audience?: string;
  /** Renew this many seconds before the token expires. Default 30 (at most half of its lifetime). */
  refreshSkewSeconds?: number;
  /** How to authenticate: HTTP Basic (default, preferred) or in the body (client_secret_post). */
  authMethod?: "basic" | "post";
  fetch?: typeof fetch;
}

/** What `getToken` asks for beyond the defaults. */
export interface TokenRequest {
  scope?: string | string[];
  audience?: string;
  /** Ignore the cached token and fetch a new one. */
  forceRefresh?: boolean;
}

/** A service token with its local expiry. */
export interface ServiceToken {
  accessToken: string;
  tokenType: "Bearer";
  /** Granted scopes, space separated. */
  scope: string;
  /** Epoch milliseconds. */
  expiresAt: number;
}

interface Entry {
  token?: ServiceToken;
  /** Epoch milliseconds after which the token is replaced. */
  refreshAt: number;
  inflight?: Promise<ServiceToken>;
}

const scopeString = (s: string | string[] | undefined): string => (Array.isArray(s) ? s.join(" ") : (s ?? "")).trim().split(/\s+/).filter(Boolean).join(" ");

/**
 * Gets and caches access tokens for calling other services with the OAuth 2.0
 * client credentials grant. A token is reused until shortly before it
 * expires, and concurrent callers share one request.
 *
 * ```ts
 * const billing = createServiceClient({ url, clientId, clientSecret, audience: "billing-api", scope: "invoices:read" });
 * const res = await billing.fetch("https://billing.internal/invoices");
 * ```
 */
export class ServiceClient {
  private readonly url: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly defaults: { scope: string; audience: string };
  private readonly skewMs: number;
  private readonly method: "basic" | "post";
  private readonly fetchImpl: typeof fetch;
  private readonly cache = new Map<string, Entry>();

  constructor(opts: ServiceClientOptions) {
    if (!opts?.url) throw new Error("warden-auth/server: `url` is required");
    if (!opts.clientId || !opts.clientSecret) throw new Error("warden-auth/server: `clientId` and `clientSecret` are required");
    if (/^(pk|sk)_/.test(opts.clientId) || /^(pk|sk)_/.test(opts.clientSecret)) {
      throw new Error("warden-auth/server: use the client id (svc_...) and secret (wcs_...) of a service client, not an API key.");
    }
    this.url = opts.url.replace(/\/+$/, "");
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    this.defaults = { scope: scopeString(opts.scope), audience: opts.audience ?? "" };
    this.skewMs = Math.max(0, opts.refreshSkewSeconds ?? 30) * 1000;
    this.method = opts.authMethod ?? "basic";
    const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (!f) throw new Error("warden-auth/server: no fetch available; use Node.js 20+ or pass `fetch`");
    this.fetchImpl = (input, init) => f(input, init);
  }

  /** A valid access token, from the cache or freshly requested. */
  async getToken(req: TokenRequest = {}): Promise<string> {
    return (await this.getTokenInfo(req)).accessToken;
  }

  /** Like getToken, with scope and expiry. */
  getTokenInfo(req: TokenRequest = {}): Promise<ServiceToken> {
    const scope = req.scope !== undefined ? scopeString(req.scope) : this.defaults.scope;
    const audience = req.audience ?? this.defaults.audience;
    const key = scope + "\n" + audience;
    let entry = this.cache.get(key);
    if (!entry) this.cache.set(key, (entry = { refreshAt: 0 }));
    if (!req.forceRefresh && entry.token && Date.now() < entry.refreshAt) return Promise.resolve(entry.token);
    // One request per scope and audience, however many callers are waiting.
    // A forced refresh still joins a request that is already running.
    const e = entry;
    const running =
      e.inflight ??
      (e.inflight = this.request(scope, audience)
        .then((r) => {
          e.token = r.token;
          e.refreshAt = r.refreshAt;
          return r.token;
        })
        .finally(() => {
          e.inflight = undefined;
        }));
    return running;
  }

  /** Forgets cached tokens, e.g. after the secret was rotated. */
  clear(): void {
    for (const e of this.cache.values()) {
      e.token = undefined;
      e.refreshAt = 0;
    }
  }

  /**
   * `fetch` with `Authorization: Bearer <service token>`. When the receiving
   * service answers 401 (the token was revoked or the keys rotated) it gets a
   * new token and retries once, if the body can be sent again.
   */
  async fetch(input: string | URL, init: RequestInit & TokenRequest = {}): Promise<Response> {
    const { scope, audience, forceRefresh, ...rest } = init;
    const send = async (force: boolean) => {
      const token = await this.getToken({ scope, audience, forceRefresh: force });
      const headers = new Headers(rest.headers);
      headers.set("Authorization", "Bearer " + token);
      return this.fetchImpl(input, { ...rest, headers });
    };
    const res = await send(!!forceRefresh);
    const replayable = rest.body == null || typeof rest.body === "string" || rest.body instanceof URLSearchParams;
    if (res.status === 401 && replayable) {
      await res.body?.cancel().catch(() => undefined);
      return send(true);
    }
    return res;
  }

  private async request(scope: string, audience: string): Promise<{ token: ServiceToken; refreshAt: number }> {
    const form = new URLSearchParams({ grant_type: "client_credentials" });
    if (scope) form.set("scope", scope);
    if (audience) form.set("audience", audience);
    const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    if (this.method === "post") {
      form.set("client_id", this.clientId);
      form.set("client_secret", this.clientSecret);
    } else {
      // RFC 6749 2.3.1: both parts are form-urlencoded before Base64.
      headers["Authorization"] = "Basic " + base64Encode(utf8.encode(encodeURIComponent(this.clientId) + ":" + encodeURIComponent(this.clientSecret)));
    }
    // Measured from before the request, so the local expiry is never later than Warden's.
    const requestedAt = Date.now();
    let res: Response;
    try {
      res = await this.fetchImpl(this.url + "/v1/oauth/token", { method: "POST", headers, body: form.toString() });
    } catch {
      throw new WardenError("network_error", "Could not reach Warden.");
    }
    let body: Record<string, unknown> | undefined;
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      body = undefined;
    }
    if (!res.ok) throw tokenError(res, body);
    const access = body?.["access_token"];
    const expiresIn = Number(body?.["expires_in"]);
    if (typeof access !== "string" || !Number.isFinite(expiresIn) || expiresIn <= 0) {
      throw new WardenError("invalid_response", "Warden returned an unexpected token response.", res.status);
    }
    const lifetimeMs = expiresIn * 1000;
    const expiresAt = requestedAt + lifetimeMs;
    return {
      token: { accessToken: access, tokenType: "Bearer", scope: typeof body?.["scope"] === "string" ? body["scope"] : "", expiresAt },
      // A skew above half of the lifetime would make short tokens useless, so it is capped there.
      refreshAt: expiresAt - Math.min(this.skewMs, lifetimeMs / 2),
    };
  }
}

/** OAuth errors (`{ error, error_description }`) and Warden's own error shape (rate limits) as WardenError. */
function tokenError(res: Response, body: Record<string, unknown> | undefined): WardenError {
  const retry = Number(res.headers.get("Retry-After"));
  const retryAfter = Number.isFinite(retry) && retry > 0 ? retry : undefined;
  const requestId = res.headers.get("X-Request-ID") ?? undefined;
  const err = body?.["error"];
  if (typeof err === "string") {
    const desc = typeof body?.["error_description"] === "string" ? body["error_description"] : "The token request failed.";
    return new WardenError(err, desc, res.status, undefined, requestId, retryAfter);
  }
  const nested = (typeof err === "object" && err !== null ? err : {}) as { code?: string; message?: string; request_id?: string };
  return new WardenError(
    nested.code ?? (res.status >= 500 ? "internal_error" : "http_error"),
    nested.message ?? `Request failed with status ${res.status}.`,
    res.status,
    undefined,
    nested.request_id ?? requestId,
    retryAfter,
  );
}

/** Creates a ServiceClient. See ServiceClientOptions. */
export function createServiceClient(opts: ServiceClientOptions): ServiceClient {
  return new ServiceClient(opts);
}

const shared = new Map<string, ServiceClient>();

/**
 * One-call helper: a cached access token for the service client, shared by
 * everything in the process that asks with the same options.
 *
 * ```ts
 * const token = await getServiceToken({ url, clientId, clientSecret, scope: "orders:read", audience: "orders-api" });
 * ```
 */
export function getServiceToken(opts: ServiceClientOptions & { forceRefresh?: boolean }): Promise<string> {
  const { forceRefresh, ...clientOpts } = opts;
  // The secret is part of the key, so a rotated secret never reuses a client built with the old one.
  const key = [clientOpts.url, clientOpts.clientId, clientOpts.clientSecret, clientOpts.authMethod ?? "basic"].join("\n");
  let client = shared.get(key);
  if (!client) shared.set(key, (client = new ServiceClient(clientOpts)));
  return client.getToken({ scope: opts.scope, audience: opts.audience, forceRefresh });
}
