/**
 * API shapes, exactly as Warden returns them (snake_case). See the OpenAPI
 * document in the admin UI (API docs > Download) for the full schema.
 */

export interface User {
  id: string;
  email?: string;
  email_verified: boolean;
  name: string;
  avatar_url?: string;
  roles: string[];
  /** Email language ("en", "tr", ...); "" means the instance default. */
  locale: string;
  mfa_enabled: boolean;
  has_password: boolean;
  created_at: string;
  last_sign_in_at?: string;
}

/** A user as seen by the server API (secret key). */
export interface ServerUser extends User {
  disabled: boolean;
  updated_at: string;
}

export interface Tokens {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  expires_at: string;
  /** Omitted in cookie mode: the refresh token is in an HttpOnly cookie. */
  refresh_token?: string;
  session_id: string;
}

/** Raw sign-in answer. The SDK turns it into an AuthResult. */
export interface AuthResponse {
  status: "authenticated" | "mfa_required" | "verification_required";
  user?: User;
  tokens?: Tokens;
  mfa_token?: string;
  new_user?: boolean;
}

/** Result of signUp, signIn, verifyMfa and social sign-in. */
export type AuthResult =
  | { status: "authenticated"; user: User; newUser: boolean }
  /** Ask for a TOTP or recovery code and call verifyMfa({ mfaToken, code }). */
  | { status: "mfa_required"; mfaToken: string; user?: User }
  /** The account exists but must verify its email before signing in. */
  | { status: "verification_required"; user?: User; newUser: boolean };

export interface Session {
  id: string;
  current: boolean;
  user_agent: string;
  ip: string;
  amr: string[];
  created_at: string;
  last_used_at: string;
  expires_at: string;
}

export interface Identity {
  provider: string;
  email?: string;
  created_at: string;
  last_used_at?: string;
}

export interface Provider {
  name: string;
  display_name: string;
  authorize_url: string;
  /** Supports native ID token sign-in (Apple, Google on mobile). */
  native: boolean;
}

export interface Providers {
  password: boolean;
  signup_enabled: boolean;
  email_verification_required: boolean;
  password_min_length: number;
  providers: Provider[];
}

export interface TotpSetup {
  /** Base32 secret for manual entry. */
  secret: string;
  /** otpauth:// URL: render it as a QR code for authenticator apps. */
  otpauth_url: string;
}

/** The signed-in state the client keeps in memory. */
export interface AuthState {
  user: User;
  accessToken: string;
  /** Epoch milliseconds. */
  expiresAt: number;
  sessionId: string;
}

/** Envelope of every webhook and RabbitMQ event. Deduplicate on `id`. */
export interface WardenEvent<T = Record<string, unknown>> {
  id: string;
  type: string;
  occurred_at: string;
  user_id?: string;
  data?: T;
}

export interface GraphQLResponse<T = Record<string, unknown>> {
  data?: T | null;
  errors?: { message: string; path?: (string | number)[]; extensions?: { code?: string; [k: string]: unknown } }[];
}
