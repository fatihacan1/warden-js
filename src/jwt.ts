import { WardenError } from "./errors.js";
import { base64Decode, getCrypto, utf8 } from "./encoding.js";

/**
 * Access token claims (RFC 9068 profile).
 *
 * Tokens come in two kinds. User tokens have a user id in `sub`, a session in
 * `sid` and `roles`. Service tokens (OAuth client credentials, for
 * service-to-service calls) have `sub: "client:<client_id>"`, `client_id` and
 * `scope`, and an empty `sid` and `roles`. Tell them apart with
 * `isServiceToken(claims)`.
 */
export interface Claims {
  /** User id, or `client:<client_id>` for service tokens. */
  sub: string;
  /** Session id: pass it to introspect or revoke. Empty on service tokens. */
  sid: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nbf?: number;
  jti?: string;
  email?: string;
  email_verified: boolean;
  roles: string[];
  /** How the user authenticated: pwd, mfa, otp, oauth:google, ... */
  amr: string[];
  /** Service tokens only: the service client that holds the token. */
  client_id?: string;
  /** Service tokens only: granted scopes, space separated (RFC 9068). */
  scope?: string;
}

/** Claims of a service token: `client_id` and `scope` are always present. */
export type ServiceClaims = Claims & { client_id: string; scope: string };

/** True for tokens issued to a service client (client credentials grant), false for user tokens. */
export function isServiceToken(claims: Pick<Claims, "client_id"> | null | undefined): claims is ServiceClaims {
  return typeof claims?.client_id === "string" && claims.client_id !== "";
}

/** The scopes of a service token as a list. User tokens have none. */
export function tokenScopes(claims: Pick<Claims, "scope"> | null | undefined): string[] {
  return typeof claims?.scope === "string" ? claims.scope.split(/\s+/).filter(Boolean) : [];
}

/** True when a service token carries the scope. Exact match. */
export function hasScope(claims: Pick<Claims, "scope"> | null | undefined, scope: string): boolean {
  return tokenScopes(claims).includes(scope);
}

interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  kid?: string;
  alg?: string;
  use?: string;
}

const invalid = (reason: string) => new WardenError("invalid_token", reason, 401);

function decodeJSON<T>(part: string): T {
  try {
    return JSON.parse(utf8.decode(base64Decode(part))) as T;
  } catch {
    throw invalid("Malformed token.");
  }
}

/**
 * Fetches and caches the JWKS. Unknown key ids trigger a refetch (Warden
 * rotates keys), rate limited so forged kids cannot hammer the endpoint.
 */
export class JwksCache {
  private keys = new Map<string, CryptoKey>();
  private fetchedAt = 0;
  private inflight: Promise<void> | null = null;

  constructor(
    private readonly url: string,
    private readonly fetchImpl: typeof fetch,
    private readonly ttlMs = 5 * 60_000,
    private readonly minRefetchMs = 30_000,
  ) {}

  async get(kid: string): Promise<CryptoKey> {
    const age = Date.now() - this.fetchedAt;
    if (this.keys.size === 0 || age > this.ttlMs || (!this.keys.has(kid) && age > this.minRefetchMs)) {
      await this.load();
    }
    const key = this.keys.get(kid);
    if (!key) throw invalid("Token signed with an unknown key.");
    return key;
  }

  private load(): Promise<void> {
    if (!this.inflight) {
      this.inflight = this.doLoad().finally(() => {
        this.inflight = null;
      });
    }
    return this.inflight;
  }

  private async doLoad(): Promise<void> {
    let res: Response;
    try {
      res = await this.fetchImpl(this.url, { headers: { Accept: "application/json" } });
    } catch {
      if (this.keys.size > 0) return; // keep serving cached keys while Warden is unreachable
      throw new WardenError("network_error", "Could not fetch the signing keys from Warden.");
    }
    if (!res.ok) {
      if (this.keys.size > 0) return;
      throw new WardenError("service_unavailable", `JWKS request failed with status ${res.status}.`, res.status);
    }
    const body = (await res.json()) as { keys?: Jwk[] };
    const next = new Map<string, CryptoKey>();
    for (const jwk of body.keys ?? []) {
      if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.kid || !jwk.x || !jwk.y) continue;
      const key = await getCrypto().subtle.importKey(
        "jwk",
        { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      next.set(jwk.kid, key);
    }
    this.keys = next;
    this.fetchedAt = Date.now();
  }
}

export interface VerifyOptions {
  issuer: string;
  audience: string | string[];
  /** Allowed clock skew in seconds. Default 30. */
  leewaySeconds?: number;
  now?: () => number;
}

/**
 * Verifies a Warden access token offline: ES256 signature against the JWKS,
 * `typ: at+jwt` (so ID tokens and other JWTs are rejected), issuer,
 * audience, expiry and not-before.
 */
export async function verifyAccessToken(token: string, jwks: JwksCache, opts: VerifyOptions): Promise<Claims> {
  if (typeof token !== "string" || token.length > 8192) throw invalid("Missing or oversized token.");
  const parts = token.split(".");
  if (parts.length !== 3) throw invalid("Malformed token.");
  const [h, p, s] = parts as [string, string, string];
  const header = decodeJSON<{ alg?: string; typ?: string; kid?: string }>(h);
  if (header.alg !== "ES256") throw invalid("Unexpected token algorithm.");
  if (header.typ !== "at+jwt") throw invalid("Not an access token.");
  if (!header.kid) throw invalid("Token has no key id.");

  const key = await jwks.get(header.kid);
  const sig = base64Decode(s);
  if (sig.length !== 64) throw invalid("Malformed signature.");
  const ok = await getCrypto().subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig as BufferSource, utf8.encode(h + "." + p) as BufferSource);
  if (!ok) throw invalid("Invalid token signature.");

  const c = decodeJSON<Claims>(p);
  const now = Math.floor((opts.now?.() ?? Date.now()) / 1000);
  const leeway = opts.leewaySeconds ?? 30;
  if (c.iss !== opts.issuer) throw invalid("Token issued by another server.");
  const want = Array.isArray(opts.audience) ? opts.audience : [opts.audience];
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!want.some((a) => aud.includes(a))) throw invalid("Token meant for another audience.");
  if (typeof c.exp !== "number" || c.exp + leeway < now) throw invalid("Token expired.");
  if (typeof c.nbf === "number" && c.nbf - leeway > now) throw invalid("Token not valid yet.");
  if (typeof c.sub !== "string" || !c.sub) throw invalid("Token has no subject.");
  if (c.client_id !== undefined) {
    // Service token: it must be about a client, never about a user session.
    if (typeof c.client_id !== "string" || !c.client_id || c.sub !== "client:" + c.client_id || c.sid) {
      throw invalid("Malformed service token.");
    }
    return { ...c, sid: "", scope: typeof c.scope === "string" ? c.scope : "", roles: [], amr: [], email_verified: false };
  }
  return { ...c, roles: Array.isArray(c.roles) ? c.roles : [], amr: Array.isArray(c.amr) ? c.amr : [], email_verified: !!c.email_verified };
}
