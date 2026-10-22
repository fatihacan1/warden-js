/**
 * Every failure from the SDK is a WardenError. `code` is stable and safe to
 * branch on; `message` is human readable and never reveals whether an
 * account exists.
 */
export class WardenError extends Error {
  override readonly name = "WardenError";

  constructor(
    /** Machine readable code, e.g. `invalid_credentials`, `rate_limited`, `network_error`. */
    readonly code: string,
    message: string,
    /** HTTP status, or 0 when the request never got a response. */
    readonly status: number = 0,
    /** Per-field validation messages, e.g. `{ password: "Use at least 8 characters." }`. */
    readonly fields?: Record<string, string>,
    /** Server request id: include it in bug reports and support tickets. */
    readonly requestId?: string,
    /** Seconds to wait before retrying (429 and 503 answers). */
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

/** Type guard for WardenError, also across bundles. */
export function isWardenError(err: unknown): err is WardenError {
  return err instanceof WardenError || (typeof err === "object" && err !== null && (err as { name?: unknown }).name === "WardenError");
}

/** Error codes Warden returns. Not exhaustive: treat unknown codes as generic failures. */
export type WardenErrorCode =
  | "validation_failed"
  | "weak_password"
  | "breached_password"
  | "invalid_credentials"
  | "unauthorized"
  | "invalid_token"
  | "invalid_mfa_code"
  | "forbidden"
  | "account_disabled"
  | "email_not_verified"
  | "reauthentication_required"
  | "signup_disabled"
  | "invalid_publishable_key"
  | "origin_not_allowed"
  | "invalid_secret_key"
  | "secret_key_in_browser"
  | "not_found"
  | "provider_not_enabled"
  | "email_taken"
  | "conflict"
  | "last_credential"
  | "mfa_already_enabled"
  | "mfa_not_enabled"
  | "invalid_redirect_uri"
  | "oauth_failed"
  | "payload_too_large"
  | "unsupported_media_type"
  | "rate_limited"
  | "server_busy"
  | "service_unavailable"
  | "internal_error"
  | "network_error"
  | "invalid_response"
  | "invalid_signature";

interface ErrorBody {
  error?: { code?: string; message?: string; fields?: Record<string, string>; request_id?: string };
}

/** Builds a WardenError from an HTTP response. */
export async function errorFromResponse(res: Response): Promise<WardenError> {
  let body: ErrorBody | undefined;
  try {
    body = (await res.json()) as ErrorBody;
  } catch {
    body = undefined;
  }
  const e = body?.error;
  const retry = Number(res.headers.get("Retry-After"));
  return new WardenError(
    e?.code ?? (res.status >= 500 ? "internal_error" : "http_error"),
    e?.message ?? `Request failed with status ${res.status}.`,
    res.status,
    e?.fields,
    e?.request_id ?? res.headers.get("X-Request-ID") ?? undefined,
    Number.isFinite(retry) && retry > 0 ? retry : undefined,
  );
}
