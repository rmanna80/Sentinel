/**
 * Links that come from outside data (advisory URLs, references) are only ever rendered when they are
 * plain http(s). This keeps javascript:, data: and other schemes from ever reaching an href.
 */
export function isHttpUrl(value: string | null | undefined): value is string {
  if (typeof value !== "string") return false;
  return /^https?:\/\//i.test(value.trim());
}
