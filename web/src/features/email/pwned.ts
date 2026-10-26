/**
 * Pwned Passwords with k-anonymity, done in the browser:
 * 1. SHA-1 the password here (crypto.subtle). The password never leaves this page.
 * 2. Send only the first 5 hex characters of the hash to Sentinel's relay.
 * 3. Compare the returned suffixes with the rest of the hash here.
 * Neither the password nor its full hash reaches Sentinel's server or Have I Been Pwned.
 */
import type { PwnedRange } from "../../api/types";

export async function sha1Hex(text: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("This browser can't compute SHA-1 here (crypto.subtle is unavailable). Open Sentinel at http://127.0.0.1.");
  }
  const digest = await subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export interface PwnedResult {
  /** How many times the password appears in known breaches; 0 when it isn't found. */
  count: number;
  /** The only thing that was sent: the first 5 characters of the SHA-1 hash. */
  prefixSent: string;
}

export async function checkPwnedPassword(
  password: string,
  fetchRange: (prefix: string) => Promise<PwnedRange>,
): Promise<PwnedResult> {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const range = await fetchRange(prefix);
  const hit = range.suffixes.find((s) => s.suffix.toUpperCase() === suffix);
  return { count: hit ? hit.count : 0, prefixSent: prefix };
}
