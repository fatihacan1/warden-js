// Small, dependency-free helpers that work in browsers, React Native,
// Node.js 20+, Deno, Bun and edge runtimes.

export function getCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.getRandomValues) {
    throw new Error(
      "warden-auth: no Web Crypto available. On React Native install react-native-get-random-values (and a SubtleCrypto polyfill for PKCE), on Node.js use version 20 or later.",
    );
  }
  return c;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  getCrypto().getRandomValues(b);
  return b;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64Decode(s: string): Uint8Array {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std + "===".slice((std.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64Encode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

export const utf8 = {
  encode: (s: string): Uint8Array => new TextEncoder().encode(s),
  decode: (b: Uint8Array): string => new TextDecoder().decode(b),
};

/** A URL-safe random string with n bytes of entropy. */
export function randomString(n = 32): string {
  return base64UrlEncode(randomBytes(n));
}

export async function sha256(input: string): Promise<Uint8Array> {
  const digest = await getCrypto().subtle.digest("SHA-256", utf8.encode(input) as BufferSource);
  return new Uint8Array(digest);
}

/** RFC 7636 PKCE pair: a random verifier and its S256 challenge. */
export async function createPkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomString(32);
  const challenge = base64UrlEncode(await sha256(verifier));
  return { verifier, challenge };
}
