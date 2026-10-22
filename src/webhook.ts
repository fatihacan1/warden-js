import { WardenError } from "./errors.js";
import { base64Decode, base64Encode, getCrypto, utf8 } from "./encoding.js";
import type { WardenEvent } from "./types.js";

type HeaderBag = Headers | Record<string, string | string[] | undefined>;

export interface VerifyWebhookInput {
  /** The endpoint's signing secret from the admin UI (whsec_...). */
  secret: string;
  /** Request headers: a Headers object, or Node/Express `req.headers`. */
  headers: HeaderBag;
  /** The raw request body, exactly as received. Not re-serialized JSON. */
  body: string | Uint8Array | ArrayBuffer;
  /** Maximum age of the request in seconds. Default 300. */
  toleranceSeconds?: number;
  now?: () => number;
}

function header(h: HeaderBag, name: string): string {
  if (typeof (h as Headers).get === "function") return (h as Headers).get(name) ?? "";
  const bag = h as Record<string, string | string[] | undefined>;
  const v = bag[name] ?? bag[name.toLowerCase()] ?? Object.entries(bag).find(([k]) => k.toLowerCase() === name)?.[1];
  return Array.isArray(v) ? (v[0] ?? "") : (v ?? "");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const bad = (msg: string) => new WardenError("invalid_signature", msg, 400);

/**
 * Verifies a webhook from Warden (Standard Webhooks) and returns the parsed
 * event. Throws a WardenError with code `invalid_signature` for forged,
 * modified or replayed requests: answer them with 400.
 */
export async function verifyWebhook<T = Record<string, unknown>>(input: VerifyWebhookInput): Promise<WardenEvent<T>> {
  const id = header(input.headers, "webhook-id");
  const ts = header(input.headers, "webhook-timestamp");
  const signatures = header(input.headers, "webhook-signature");
  if (!id || !ts || !signatures) throw bad("Missing webhook-id, webhook-timestamp or webhook-signature header.");

  const sent = Number(ts);
  const now = Math.floor((input.now?.() ?? Date.now()) / 1000);
  const tolerance = input.toleranceSeconds ?? 300;
  if (!Number.isInteger(sent) || Math.abs(now - sent) > tolerance) throw bad("Webhook timestamp is too old or in the future.");

  const body =
    typeof input.body === "string" ? utf8.encode(input.body) : input.body instanceof ArrayBuffer ? new Uint8Array(input.body) : input.body;
  if (!(body instanceof Uint8Array)) {
    throw bad("Pass the raw request body (string or bytes). With Express use express.raw({ type: \"application/json\" }).");
  }
  const secret = input.secret.startsWith("whsec_") ? input.secret.slice(6) : input.secret;
  let keyBytes: Uint8Array;
  try {
    keyBytes = base64Decode(secret);
  } catch {
    throw new WardenError("invalid_signature", "The webhook secret is malformed: copy it again from the admin UI.");
  }
  const key = await getCrypto().subtle.importKey("raw", keyBytes as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const prefix = utf8.encode(`${id}.${ts}.`);
  const signed = new Uint8Array(prefix.length + body.length);
  signed.set(prefix);
  signed.set(body, prefix.length);
  const expected = "v1," + base64Encode(new Uint8Array(await getCrypto().subtle.sign("HMAC", key, signed as BufferSource)));

  if (!signatures.split(" ").some((s) => timingSafeEqual(s.trim(), expected))) throw bad("Webhook signature does not match.");

  try {
    return JSON.parse(utf8.decode(body)) as WardenEvent<T>;
  } catch {
    throw bad("Webhook body is not JSON.");
  }
}
