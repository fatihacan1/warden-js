/**
 * warden-auth/server: for your backends (Node.js 20+, Bun, Deno, edge).
 *
 * - verifyToken(): offline access token verification against Warden's JWKS
 * - express(): middleware with optional role and scope requirements
 * - createServiceClient() / getServiceToken(): tokens for calling other services (OAuth client credentials)
 * - users / introspect / graphql: the server API, with a secret key
 * - verifyWebhook(): Standard Webhooks signature check
 *
 * Never import this file into a browser or mobile bundle with a secret key.
 */
import { WardenError, errorFromResponse } from "./errors.js";
import { JwksCache, hasScope, isServiceToken, tokenScopes, verifyAccessToken, type Claims } from "./jwt.js";
import { ServiceClient, type ServiceClientOptions } from "./service.js";
import type { GraphQLResponse, ServerUser } from "./types.js";

export { verifyWebhook, type VerifyWebhookInput } from "./webhook.js";
export { WardenError, isWardenError } from "./errors.js";
export { isServiceToken, hasScope, tokenScopes, type Claims, type ServiceClaims } from "./jwt.js";
export {
  ServiceClient,
  createServiceClient,
  getServiceToken,
  type ServiceClientOptions,
  type ServiceToken,
  type TokenRequest,
} from "./service.js";
export type { ServerUser, User, WardenEvent, GraphQLResponse } from "./types.js";

export interface WardenServerOptions {
  /** Base URL of your Warden instance. */
  url: string;
  /** Secret key (sk_live_...) for the server API. Not needed to verify tokens. */
  secretKey?: string;
  /** Expected `iss`. Defaults to `url` (Warden's default when TOKEN_ISSUER is unset). */
  issuer?: string;
  /** Expected `aud`, Warden's TOKEN_AUDIENCE. Default "warden". */
  audience?: string | string[];
  /** Allowed clock skew in seconds. Default 30. */
  leewaySeconds?: number;
  /** How long fetched keys are trusted before a refresh. Default 5 minutes. */
  jwksCacheSeconds?: number;
  fetch?: typeof fetch;
}

/** A request as seen by the helpers: Express, Fastify, Node http, or a Fetch API Request. */
export type RequestLike = { headers: Headers | Record<string, string | string[] | undefined> };

export interface ExpressOptions {
  /** The user needs at least one of these roles. Does not apply to service tokens, which have no roles. */
  roles?: string[];
  /** The user needs every one of these roles. Does not apply to service tokens. */
  allRoles?: string[];
  /**
   * Accept service tokens (client credentials, for service-to-service calls)
   * that carry every one of these scopes. User tokens are not affected. Without
   * `scopes` or `allowServiceTokens`, service tokens are refused with 403, so a
   * route written for users never runs for a machine by accident.
   */
  scopes?: string[];
  /** Accept service tokens without requiring particular scopes. Prefer `scopes`. */
  allowServiceTokens?: boolean;
  /** Only accept service tokens: for internal endpoints that users must never call. Implies `allowServiceTokens`. */
  serviceOnly?: boolean;
  /** Let requests without a token through (req.auth stays undefined). */
  optional?: boolean;
  /** Also ask Warden whether the session is still active (one network call per request). */
  checkSession?: boolean;
  /** Customize the error response, e.g. with brw-res-formatter's sendErrorResponse. */
  onError?: (err: WardenError, req: unknown, res: unknown, next: (err?: unknown) => void) => void;
}

export interface Introspection {
  active: boolean;
  reason?: "invalid_token" | "session_revoked" | "user_disabled" | "client_revoked";
  /** "service" for tokens of a service client; absent on user tokens. */
  token_type?: "service";
  /** Service tokens: `client:<client_id>`. */
  sub?: string;
  client_id?: string;
  client_name?: string;
  /** Service tokens: granted scopes, space separated. */
  scope?: string;
  aud?: string[];
  user_id?: string;
  session_id?: string;
  email?: string;
  email_verified?: boolean;
  roles?: string[];
  amr?: string[];
  expires_at?: string;
}

/**
 * Fields of req.auth set by the Express middleware. For service tokens
 * `userId` and `sessionId` are empty strings: check `clientId` or use
 * `isServiceToken(req.auth)`.
 */
export interface AuthContext extends Claims {
  userId: string;
  sessionId: string;
  /** Set when the caller is a service client. */
  clientId?: string;
  /** Scopes of a service token; empty for users. */
  scopes: string[];
}

/** True when the claims carry the role. Exact match, never substrings. */
export function hasRole(claims: Pick<Claims, "roles"> | null | undefined, role: string): boolean {
  return !!claims?.roles?.includes(role);
}

/** Extracts a bearer token from an Authorization header value or a request. */
export function bearerToken(input: string | RequestLike | null | undefined): string | null {
  let h: string | undefined;
  if (typeof input === "string") h = input;
  else if (input?.headers) {
    const hs = input.headers;
    const v = typeof (hs as Headers).get === "function" ? (hs as Headers).get("authorization") : (hs as Record<string, string | string[] | undefined>)["authorization"];
    h = Array.isArray(v) ? v[0] : (v ?? undefined);
  }
  const m = /^Bearer\s+(.+)$/i.exec(h?.trim() ?? "");
  return m?.[1]?.trim() || null;
}

export class WardenServer {
  readonly url: string;
  private readonly secretKey?: string;
  private readonly issuer: string;
  private readonly audience: string | string[];
  private readonly leeway: number;
  private readonly fetchImpl: typeof fetch;
  private readonly jwks: JwksCache;

  constructor(opts: WardenServerOptions) {
    if (!opts?.url) throw new Error("warden-auth/server: `url` is required");
    this.url = opts.url.replace(/\/+$/, "");
    this.secretKey = opts.secretKey;
    if (opts.secretKey && !opts.secretKey.startsWith("sk_")) {
      throw new Error("warden-auth/server: `secretKey` must be a secret key (sk_...), not a publishable key.");
    }
    this.issuer = opts.issuer ?? this.url;
    this.audience = opts.audience ?? "warden";
    this.leeway = opts.leewaySeconds ?? 30;
    const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (!f) throw new Error("warden-auth/server: no fetch available; use Node.js 20+ or pass `fetch`");
    this.fetchImpl = (input, init) => f(input, init);
    this.jwks = new JwksCache(this.url + "/.well-known/jwks.json", this.fetchImpl, (opts.jwksCacheSeconds ?? 300) * 1000);
  }

  /**
   * Verifies an access token offline (no call to Warden per request; keys are
   * cached). Throws WardenError `invalid_token` (status 401) when invalid.
   */
  verifyToken(token: string): Promise<Claims> {
    return verifyAccessToken(token, this.jwks, { issuer: this.issuer, audience: this.audience, leewaySeconds: this.leeway });
  }

  /** Verifies the bearer token of a request. */
  async authenticate(req: RequestLike | string): Promise<Claims> {
    const token = bearerToken(req);
    if (!token) throw new WardenError("unauthorized", "Authentication is required.", 401);
    return this.verifyToken(token);
  }

  /**
   * Express/Connect middleware. Sets `req.auth` (claims plus userId and
   * sessionId) or answers 401/403 with Warden's error shape.
   *
   * ```ts
   * app.get("/admin", warden.express({ roles: ["admin"] }), handler);
   * ```
   */
  express(opts: ExpressOptions = {}) {
    return (req: RequestLike & { auth?: AuthContext }, res: unknown, next: (err?: unknown) => void): void => {
      const fail = (err: WardenError) => {
        if (opts.onError) return opts.onError(err, req, res, next);
        const r = res as { status(code: number): { json(body: unknown): void }; setHeader?(k: string, v: string): void };
        if (err.status === 401) r.setHeader?.("WWW-Authenticate", 'Bearer realm="api"');
        r.status(err.status || 401).json({ error: { code: err.code, message: err.message } });
      };
      const token = bearerToken(req);
      if (!token) {
        if (opts.optional) return next();
        return fail(new WardenError("unauthorized", "Authentication is required.", 401));
      }
      this.verifyToken(token)
        .then(async (claims) => {
          const forbidden = (msg = "You are not allowed to perform this action.") => new WardenError("forbidden", msg, 403);
          if (isServiceToken(claims)) {
            if (!opts.scopes && !opts.allowServiceTokens && !opts.serviceOnly) {
              throw forbidden("Service tokens are not accepted here.");
            }
            if (opts.scopes?.some((s) => !hasScope(claims, s))) throw forbidden("The token is missing a required scope.");
            if (opts.checkSession) {
              const r = await this.introspect(token);
              if (!r.active) throw new WardenError("invalid_token", "The service client was revoked.", 401);
            }
            req.auth = { ...claims, userId: "", sessionId: "", clientId: claims.client_id, scopes: tokenScopes(claims) };
            return next();
          }
          if (opts.serviceOnly) throw forbidden("Only service clients may call this endpoint.");
          if (opts.checkSession) {
            const r = await this.introspect(token, { checkSession: true });
            if (!r.active) throw new WardenError("invalid_token", "The session has ended.", 401);
            claims = { ...claims, roles: r.roles ?? claims.roles };
          }
          if (opts.roles?.length && !opts.roles.some((r) => hasRole(claims, r))) throw forbidden();
          if (opts.allRoles?.length && !opts.allRoles.every((r) => hasRole(claims, r))) throw forbidden();
          req.auth = { ...claims, userId: claims.sub, sessionId: claims.sid, scopes: [] };
          next();
        })
        .catch((err: unknown) => (err instanceof WardenError ? fail(err) : next(err)));
    };
  }

  /**
   * A client for calling other services as this service: caches the access
   * token until shortly before it expires and shares one request between
   * concurrent callers. Uses this server's Warden URL and fetch.
   */
  serviceClient(opts: Omit<ServiceClientOptions, "url">): ServiceClient {
    return new ServiceClient({ fetch: this.fetchImpl, ...opts, url: this.url });
  }

  // -------------------------------------------------------------------------
  // Server API (secret key)

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    if (!this.secretKey) throw new Error("warden-auth/server: pass `secretKey` to use the server API.");
    let res: Response;
    try {
      res = await this.fetchImpl(this.url + path, {
        method,
        headers: { Authorization: "Bearer " + this.secretKey, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new WardenError("network_error", "Could not reach Warden.");
    }
    if (!res.ok) throw await errorFromResponse(res);
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /**
   * Online token check: also rejects revoked sessions and, with
   * `checkSession`, disabled users, and returns the user's current roles.
   * Use it for sensitive actions; verifyToken is enough for everything else.
   */
  introspect(token: string, opts: { checkSession?: boolean } = {}): Promise<Introspection> {
    return this.call<Introspection>("POST", "/v1/server/tokens/verify", { token, check_session: !!opts.checkSession });
  }

  readonly users = {
    /** Creates a user, even when sign-ups are off. Use it to create your first admin. */
    create: (input: { email: string; password?: string; name?: string; roles?: string[]; emailVerified?: boolean; locale?: string }): Promise<ServerUser> =>
      this.call<ServerUser>("POST", "/v1/server/users", {
        email: input.email,
        password: input.password,
        name: input.name,
        roles: input.roles,
        email_verified: input.emailVerified,
        locale: input.locale,
      }),
    get: (id: string): Promise<ServerUser> => this.call<ServerUser>("GET", "/v1/server/users/" + encodeURIComponent(id)),
    /** Resolves to null when no user has this email. */
    findByEmail: async (email: string): Promise<ServerUser | null> => {
      try {
        return await this.call<ServerUser>("GET", "/v1/server/users?email=" + encodeURIComponent(email));
      } catch (err) {
        if (err instanceof WardenError && err.status === 404) return null;
        throw err;
      }
    },
    /** Changes name, roles (replaces the list) or disabled state. Disabling signs the user out everywhere. */
    update: (id: string, input: { name?: string; roles?: string[]; disabled?: boolean; locale?: string }): Promise<ServerUser> =>
      this.call<ServerUser>("PATCH", "/v1/server/users/" + encodeURIComponent(id), input),
    /** Adds roles, keeping existing ones. */
    addRoles: async (id: string, roles: string[]): Promise<ServerUser> => {
      const u = await this.users.get(id);
      return this.users.update(id, { roles: Array.from(new Set([...u.roles, ...roles])) });
    },
    removeRoles: async (id: string, roles: string[]): Promise<ServerUser> => {
      const u = await this.users.get(id);
      return this.users.update(id, { roles: u.roles.filter((r) => !roles.includes(r)) });
    },
    /** Signs the user out on every device. Resolves to the number of sessions ended. */
    revokeSessions: async (id: string): Promise<number> =>
      (await this.call<{ revoked: number }>("DELETE", "/v1/server/users/" + encodeURIComponent(id) + "/sessions")).revoked,
  };

  /** Server-side GraphQL with the secret key (user(id), setUserRoles). */
  graphql<T = Record<string, unknown>>(query: string, variables?: Record<string, unknown>): Promise<GraphQLResponse<T>> {
    return this.call<GraphQLResponse<T>>("POST", "/graphql", { query, variables });
  }
}

/** Creates a server helper. See WardenServerOptions. */
export function createWardenServer(opts: WardenServerOptions): WardenServer {
  return new WardenServer(opts);
}
