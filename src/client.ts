import { WardenError, errorFromResponse } from "./errors.js";
import { createPkce, randomString, sha256 } from "./encoding.js";
import { browserStorage, isBrowser, memoryStorage, type StorageAdapter } from "./storage.js";
import type {
  AuthResponse,
  AuthResult,
  AuthState,
  GraphQLResponse,
  Identity,
  Providers,
  Session,
  TotpSetup,
  User,
} from "./types.js";

export interface WardenClientOptions {
  /** Base URL of your Warden instance, e.g. https://auth.example.com */
  url: string;
  /** Publishable key from the admin UI (pk_live_... / pk_test_...). Public by design. */
  publishableKey?: string;
  /**
   * How the refresh token is kept.
   * - "cookie": in an HttpOnly cookie set by Warden. Best for browsers: scripts can never read it.
   * - "token": returned in JSON and kept in `storage`. For React Native and other non-browser apps.
   * Defaults to "cookie" in browsers and "token" elsewhere.
   */
  mode?: "cookie" | "token";
  /** Persists the refresh token in token mode. Use a secure store on mobile. Defaults to memory. */
  storage?: StorageAdapter;
  /** Keeps PKCE state across the social sign-in redirect. Defaults to sessionStorage in browsers. */
  flowStorage?: StorageAdapter;
  /** Prefix of storage keys. Default "warden". */
  storageKey?: string;
  /** Refresh this many seconds before the access token expires. Default 30. */
  refreshMarginSeconds?: number;
  /** Custom fetch (tests, React Native polyfills, instrumentation). */
  fetch?: typeof fetch;
}

type Listener = (state: AuthState | null) => void;

interface RequestOptions {
  body?: unknown;
  form?: FormData;
  raw?: BodyInit;
  contentType?: string;
  auth?: boolean;
  /** Auth endpoints: send X-Auth-Mode and cookies in cookie mode. */
  authFlow?: boolean;
  /** Internal: do not retry after a refresh. */
  retried?: boolean;
}

/** React Native file reference, as returned by image pickers. */
export interface NativeFile {
  uri: string;
  name?: string;
  type?: string;
}

/**
 * Warden client for web and mobile apps.
 *
 * ```ts
 * const warden = createWarden({ url: "https://auth.example.com", publishableKey: "pk_live_..." });
 * await warden.restore();                       // on app start
 * const res = await warden.signIn({ email, password });
 * ```
 */
export class WardenClient {
  readonly url: string;
  readonly mode: "cookie" | "token";
  private readonly key?: string;
  private readonly storage: StorageAdapter;
  private readonly flowStorage: StorageAdapter;
  private readonly prefix: string;
  private readonly margin: number;
  private readonly fetchImpl: typeof fetch;
  private state: AuthState | null = null;
  private refreshing: Promise<AuthState | null> | null = null;
  private readonly listeners = new Set<Listener>();

  constructor(opts: WardenClientOptions) {
    if (!opts?.url) throw new Error("warden-auth: `url` is required");
    this.url = opts.url.replace(/\/+$/, "");
    this.key = opts.publishableKey;
    if (this.key?.startsWith("sk_")) {
      throw new Error("warden-auth: a secret key (sk_...) must never be used in an app. Use a publishable key (pk_...); secret keys belong in warden-auth/server on your backend.");
    }
    this.mode = opts.mode ?? (isBrowser() ? "cookie" : "token");
    this.storage = opts.storage ?? memoryStorage();
    this.flowStorage = opts.flowStorage ?? (isBrowser() ? browserStorage("session") : this.storage);
    this.prefix = opts.storageKey ?? "warden";
    this.margin = (opts.refreshMarginSeconds ?? 30) * 1000;
    const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (!f) throw new Error("warden-auth: no fetch available; pass `fetch` in the options");
    this.fetchImpl = (input, init) => f(input, init);
  }

  // -------------------------------------------------------------------------
  // State

  /** The signed-in state, or null. Synchronous: no network call. */
  getSession(): AuthState | null {
    return this.state;
  }

  /** Called whenever the user signs in, refreshes, updates the profile or signs out. Returns an unsubscribe function. */
  onAuthStateChange(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private setState(next: AuthState | null) {
    this.state = next;
    for (const l of this.listeners) {
      try {
        l(next);
      } catch {
        /* a listener must not break the client */
      }
    }
  }

  private refreshKey() {
    return this.prefix + ".refresh_token";
  }

  private async acceptAuth(res: AuthResponse): Promise<AuthResult> {
    if (res.status === "mfa_required") {
      return { status: "mfa_required", mfaToken: res.mfa_token ?? "", user: res.user };
    }
    if (res.status === "verification_required" || !res.tokens) {
      return { status: "verification_required", user: res.user, newUser: !!res.new_user };
    }
    const t = res.tokens;
    if (this.mode === "token" && t.refresh_token) {
      await this.storage.setItem(this.refreshKey(), t.refresh_token);
    }
    const user = res.user ?? this.state?.user;
    if (!user) throw new WardenError("invalid_response", "Warden answered without a user.");
    this.setState({ user, accessToken: t.access_token, expiresAt: Date.parse(t.expires_at) || Date.now() + t.expires_in * 1000, sessionId: t.session_id });
    return { status: "authenticated", user, newUser: !!res.new_user };
  }

  private async clear() {
    await this.storage.removeItem(this.refreshKey());
    if (this.state) this.setState(null);
  }

  // -------------------------------------------------------------------------
  // HTTP

  private async request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.key) headers["X-Warden-Key"] = this.key;
    let body: BodyInit | undefined;
    if (opts.form) body = opts.form;
    else if (opts.raw !== undefined) {
      body = opts.raw;
      if (opts.contentType) headers["Content-Type"] = opts.contentType;
    } else if (opts.body !== undefined) {
      body = JSON.stringify(opts.body);
      headers["Content-Type"] = "application/json";
    }
    const cookie = this.mode === "cookie" && opts.authFlow;
    if (cookie) headers["X-Auth-Mode"] = "cookie";
    if (opts.auth) {
      const token = await this.getAccessToken();
      if (!token) throw new WardenError("unauthorized", "Sign in first.", 401);
      headers["Authorization"] = "Bearer " + token;
    }
    let res: Response;
    try {
      res = await this.fetchImpl(this.url + path, { method, headers, body, credentials: cookie ? "include" : "omit" });
    } catch (err) {
      throw new WardenError("network_error", "Could not reach the authentication server. Check the connection and try again.", 0, undefined, undefined, undefined);
    }
    if (!res.ok) {
      const err = await errorFromResponse(res);
      // The access token may have been revoked or rotated server side: refresh once and retry.
      if (opts.auth && !opts.retried && err.status === 401 && err.code === "invalid_token") {
        const next = await this.refresh();
        if (next) return this.request<T>(method, path, { ...opts, retried: true });
      }
      throw err;
    }
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    if (!text) return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new WardenError("invalid_response", "The server sent an unexpected response.", res.status);
    }
  }

  // -------------------------------------------------------------------------
  // Sessions

  /**
   * Restores the session on app start, using the refresh cookie (cookie mode)
   * or the stored refresh token (token mode). Resolves to null when signed out.
   */
  async restore(): Promise<AuthState | null> {
    if (this.mode === "token" && !(await this.storage.getItem(this.refreshKey()))) return null;
    try {
      return await this.refresh();
    } catch (err) {
      if (err instanceof WardenError && err.code === "network_error") throw err;
      return null;
    }
  }

  /**
   * Gets a new access token. Concurrent callers share one request: Warden
   * rotates refresh tokens on every use and treats parallel reuse as theft.
   */
  refresh(): Promise<AuthState | null> {
    if (!this.refreshing) {
      this.refreshing = this.doRefresh().finally(() => {
        this.refreshing = null;
      });
    }
    return this.refreshing;
  }

  private async doRefresh(): Promise<AuthState | null> {
    let body: { refresh_token?: string } = {};
    if (this.mode === "token") {
      const rt = await this.storage.getItem(this.refreshKey());
      if (!rt) {
        await this.clear();
        return null;
      }
      body = { refresh_token: rt };
    }
    try {
      const res = await this.request<AuthResponse>("POST", "/v1/auth/refresh", { body, authFlow: true });
      await this.acceptAuth(res);
      return this.state;
    } catch (err) {
      if (err instanceof WardenError && (err.code === "invalid_token" || err.code === "account_disabled" || err.status === 401)) {
        await this.clear();
        return null;
      }
      throw err;
    }
  }

  /** A valid access token, refreshed when it is about to expire. Null when signed out. */
  async getAccessToken(): Promise<string | null> {
    const s = this.state;
    if (s && s.expiresAt - Date.now() > this.margin) return s.accessToken;
    if (!s && this.mode === "token" && !(await this.storage.getItem(this.refreshKey()))) return null;
    const next = await this.refresh();
    return next?.accessToken ?? null;
  }

  /**
   * fetch() for your own APIs: adds `Authorization: Bearer <access token>`,
   * refreshes it when needed, and retries once on a 401.
   */
  async fetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    const send = async (token: string | null) => {
      const headers = new Headers(init.headers);
      if (token) headers.set("Authorization", "Bearer " + token);
      return this.fetchImpl(input, { ...init, headers });
    };
    const res = await send(await this.getAccessToken());
    if (res.status !== 401 || !this.state) return res;
    const next = await this.refresh();
    return next ? send(next.accessToken) : res;
  }

  // -------------------------------------------------------------------------
  // Email and password

  /** Sign-in methods and public settings of this instance. */
  providers(): Promise<Providers> {
    return this.request<Providers>("GET", "/v1/auth/providers");
  }

  /** Creates an account. `locale` sets the email language (defaults to the browser's, then the instance default). */
  async signUp(input: { email: string; password: string; name?: string; locale?: string }): Promise<AuthResult> {
    return this.acceptAuth(await this.request<AuthResponse>("POST", "/v1/auth/signup", { body: input, authFlow: true }));
  }

  async signIn(input: { email: string; password: string }): Promise<AuthResult> {
    return this.acceptAuth(await this.request<AuthResponse>("POST", "/v1/auth/signin", { body: input, authFlow: true }));
  }

  /** Completes a sign-in that answered `mfa_required`, with a TOTP or recovery code. */
  async verifyMfa(input: { mfaToken: string; code: string }): Promise<AuthResult> {
    return this.acceptAuth(
      await this.request<AuthResponse>("POST", "/v1/auth/mfa/verify", { body: { mfa_token: input.mfaToken, code: input.code }, authFlow: true }),
    );
  }

  /** Signs out this device. Local state is cleared even if the network call fails. */
  async signOut(): Promise<void> {
    const rt = this.mode === "token" ? await this.storage.getItem(this.refreshKey()) : undefined;
    const token = this.state?.accessToken;
    try {
      const headers: Record<string, string> = {};
      if (this.key) headers["X-Warden-Key"] = this.key;
      if (this.mode === "cookie") headers["X-Auth-Mode"] = "cookie";
      if (token) headers["Authorization"] = "Bearer " + token;
      headers["Content-Type"] = "application/json";
      await this.fetchImpl(this.url + "/v1/auth/signout", {
        method: "POST",
        headers,
        body: JSON.stringify(rt ? { refresh_token: rt } : {}),
        credentials: this.mode === "cookie" ? "include" : "omit",
      });
    } catch {
      /* offline: the session expires on its own */
    } finally {
      await this.clear();
    }
  }

  readonly password = {
    /** Sends a reset link. Always resolves, whether or not the account exists. */
    forgot: (email: string): Promise<void> => this.request<void>("POST", "/v1/auth/password/forgot", { body: { email } }).then(() => undefined),
    /** Sets a new password with the token from the reset link. Other devices are signed out. */
    reset: (input: { token: string; password: string }): Promise<void> =>
      this.request<void>("POST", "/v1/auth/password/reset", { body: input }).then(() => undefined),
    /** Changes the password of the signed-in user (sets one for social-only accounts). */
    change: (input: { currentPassword?: string; newPassword: string }): Promise<void> =>
      this.request<void>("POST", "/v1/me/password", {
        auth: true,
        body: { current_password: input.currentPassword ?? "", new_password: input.newPassword },
      }),
  };

  readonly email = {
    /** Confirms an email address with the token from the verification link. */
    verify: (token: string): Promise<void> => this.request<void>("POST", "/v1/auth/email/verify", { body: { token } }).then(() => undefined),
    /** Sends the verification email again to the signed-in user. */
    resend: (): Promise<void> => this.request<void>("POST", "/v1/me/email/resend", { auth: true }).then(() => undefined),
  };

  // -------------------------------------------------------------------------
  // Profile

  readonly user = {
    /** Loads the current user from Warden (also checks the session is still active). */
    get: async (): Promise<User> => this.updateUser(await this.request<User>("GET", "/v1/me", { auth: true })),
    /** Changes profile fields. `locale: ""` resets the email language to the instance default. */
    update: async (input: { name?: string; locale?: string }): Promise<User> =>
      this.updateUser(await this.request<User>("PATCH", "/v1/me", { auth: true, body: input })),
    /**
     * Uploads a profile photo (JPEG, PNG, GIF or WebP). Accepts a File/Blob
     * from an <input type="file">, raw bytes, or a React Native `{ uri, name, type }`.
     * Warden strips metadata and stores a 512x512 JPEG.
     */
    uploadAvatar: async (file: Blob | ArrayBuffer | Uint8Array | NativeFile, contentType?: string): Promise<User> => {
      let opts: RequestOptions;
      if (typeof Blob !== "undefined" && file instanceof Blob) {
        const form = new FormData();
        form.append("file", file, (file as File).name ?? "avatar");
        opts = { form };
      } else if (file instanceof ArrayBuffer || ArrayBuffer.isView(file)) {
        opts = { raw: file as BodyInit, contentType: contentType ?? "application/octet-stream" };
      } else {
        const f = file as NativeFile;
        const form = new FormData();
        // React Native's FormData accepts { uri, name, type } objects.
        form.append("file", { uri: f.uri, name: f.name ?? "avatar.jpg", type: f.type ?? contentType ?? "image/jpeg" } as unknown as Blob);
        opts = { form };
      }
      return this.updateUser(await this.request<User>("PUT", "/v1/me/avatar", { ...opts, auth: true }));
    },
    deleteAvatar: async (): Promise<void> => {
      await this.request<void>("DELETE", "/v1/me/avatar", { auth: true });
      if (this.state) this.updateUser({ ...this.state.user, avatar_url: undefined });
    },
    /** Deletes the account permanently. Requires the password, or a recent sign-in for social-only accounts. */
    delete: async (input: { password?: string } = {}): Promise<void> => {
      await this.request<void>("DELETE", "/v1/me", { auth: true, body: { password: input.password ?? "" } });
      await this.clear();
    },
  };

  private updateUser(user: User): User {
    if (this.state) this.setState({ ...this.state, user });
    return user;
  }

  // -------------------------------------------------------------------------
  // Devices and linked accounts

  readonly sessions = {
    /** Signed-in devices; `current` marks this one. */
    list: async (): Promise<Session[]> => (await this.request<{ sessions: Session[] }>("GET", "/v1/me/sessions", { auth: true })).sessions,
    /** Signs out one device. */
    revoke: (id: string): Promise<void> => this.request<void>("DELETE", "/v1/me/sessions/" + encodeURIComponent(id), { auth: true }),
    /** Signs out every device except this one. Resolves to how many were signed out. */
    revokeOthers: async (): Promise<number> => (await this.request<{ revoked: number }>("DELETE", "/v1/me/sessions", { auth: true })).revoked,
  };

  readonly identities = {
    list: async (): Promise<Identity[]> => (await this.request<{ identities: Identity[] }>("GET", "/v1/me/identities", { auth: true })).identities,
    /** Unlinks a social account. Fails with `last_credential` if it is the only way to sign in. */
    unlink: (provider: string): Promise<void> => this.request<void>("DELETE", "/v1/me/identities/" + encodeURIComponent(provider), { auth: true }),
  };

  // -------------------------------------------------------------------------
  // Two-factor authentication

  readonly mfa = {
    /** Starts enrollment: show `otpauth_url` as a QR code, then call enableTotp with a code from the app. */
    setupTotp: (): Promise<TotpSetup> => this.request<TotpSetup>("POST", "/v1/me/mfa/totp/setup", { auth: true, body: {} }),
    /** Confirms enrollment. Returns recovery codes: show them once and ask the user to save them. */
    enableTotp: async (code: string): Promise<string[]> => {
      const res = await this.request<{ recovery_codes: string[] }>("POST", "/v1/me/mfa/totp/enable", { auth: true, body: { code } });
      if (this.state) this.updateUser({ ...this.state.user, mfa_enabled: true });
      return res.recovery_codes;
    },
    disableTotp: async (code: string): Promise<void> => {
      await this.request<void>("POST", "/v1/me/mfa/totp/disable", { auth: true, body: { code } });
      if (this.state) this.updateUser({ ...this.state.user, mfa_enabled: false });
    },
    regenerateRecoveryCodes: async (code: string): Promise<string[]> =>
      (await this.request<{ recovery_codes: string[] }>("POST", "/v1/me/mfa/recovery-codes", { auth: true, body: { code } })).recovery_codes,
  };

  // -------------------------------------------------------------------------
  // Social sign-in

  readonly oauth = {
    /**
     * Builds the URL that starts a social sign-in (PKCE) and remembers the
     * verifier. `redirectUri` must be listed in the instance's allowed
     * redirect URIs (web page or app scheme like myapp://auth/callback).
     */
    getAuthorizationUrl: async (provider: string, input: { redirectUri: string }): Promise<string> => {
      const { verifier, challenge } = await createPkce();
      const state = randomString(16);
      await this.flowStorage.setItem(this.prefix + ".oauth", JSON.stringify({ verifier, state, redirectUri: input.redirectUri, provider }));
      const q = new URLSearchParams({ redirect_uri: input.redirectUri, code_challenge: challenge, code_challenge_method: "S256", state });
      if (this.key) q.set("client_key", this.key);
      return `${this.url}/v1/oauth/${encodeURIComponent(provider)}/authorize?${q}`;
    },
    /** Browser only: navigates to the provider. Call handleRedirect on the redirect page. */
    signInWithRedirect: async (provider: string, input: { redirectUri: string }): Promise<void> => {
      const url = await this.oauth.getAuthorizationUrl(provider, input);
      (globalThis as unknown as { location: Location }).location.assign(url);
    },
    /**
     * Finishes a social sign-in on the redirect page (or with the URL your
     * mobile app received). Checks the state, then exchanges the one-time code.
     */
    handleRedirect: async (url: string = (globalThis as unknown as { location?: Location }).location?.href ?? ""): Promise<AuthResult> => {
      const params = new URL(url).searchParams;
      const raw = await this.flowStorage.getItem(this.prefix + ".oauth");
      await this.flowStorage.removeItem(this.prefix + ".oauth");
      if (params.get("error")) {
        throw new WardenError(params.get("error") ?? "oauth_failed", params.get("error_description") ?? "Sign-in was cancelled or failed.", 400);
      }
      const flow = raw ? (JSON.parse(raw) as { verifier: string; state: string; redirectUri: string }) : null;
      const code = params.get("code");
      if (!flow || !code || params.get("state") !== flow.state) {
        throw new WardenError("invalid_token", "This sign-in link is invalid or was already used. Please start again.", 400);
      }
      return this.acceptAuth(
        await this.request<AuthResponse>("POST", "/v1/oauth/token", {
          body: { code, code_verifier: flow.verifier, redirect_uri: flow.redirectUri },
          authFlow: true,
        }),
      );
    },
    /**
     * Native sign-in with an ID token from Sign in with Apple or Google
     * Sign-In. Pass the raw nonce; give the platform SDK `await hashNonce(nonce)`
     * where it asks for a hashed nonce (Apple).
     */
    signInWithIdToken: async (provider: "apple" | "google" | string, input: { idToken: string; nonce: string; name?: string }): Promise<AuthResult> =>
      this.acceptAuth(
        await this.request<AuthResponse>("POST", `/v1/oauth/${encodeURIComponent(provider)}/native`, {
          body: { id_token: input.idToken, nonce: input.nonce, name: input.name ?? "" },
          authFlow: true,
        }),
      ),
    /** A fresh nonce for native sign-in (single use). */
    createNonce: (): string => randomString(24),
  };

  // -------------------------------------------------------------------------
  // GraphQL

  /** Sends one operation to POST /graphql (when the instance enables it). */
  async graphql<T = Record<string, unknown>>(query: string, variables?: Record<string, unknown>): Promise<GraphQLResponse<T>> {
    const auth = !!this.state || (this.mode === "token" && !!(await this.storage.getItem(this.refreshKey())));
    return this.request<GraphQLResponse<T>>("POST", "/graphql", { body: { query, variables }, auth });
  }
}

/** hex(SHA-256(nonce)), the hashed nonce Apple's SDK expects. */
export async function hashNonce(nonce: string): Promise<string> {
  return Array.from(await sha256(nonce), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Creates a client. See WardenClientOptions. */
export function createWarden(opts: WardenClientOptions): WardenClient {
  return new WardenClient(opts);
}
