// Dates arrive as ISO UTC strings; everything shown is in the browser's local time.

export function parseDate(value: unknown): Date | null {
  if (typeof value !== "string" && !(value instanceof Date)) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

const dateTimeFmt = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const shortFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const dayFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });
const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto", style: "long" });

export function formatDateTime(value: unknown): string {
  const d = parseDate(value);
  return d ? dateTimeFmt.format(d) : "Unknown";
}

export function formatShort(value: unknown, now = new Date()): string {
  const d = parseDate(value);
  if (!d) return "Unknown";
  return d.getFullYear() === now.getFullYear() ? shortFmt.format(d) : dateTimeFmt.format(d);
}

export function formatTime(value: unknown): string {
  const d = parseDate(value);
  return d ? timeFmt.format(d) : "";
}

export function formatDay(value: unknown): string {
  const d = parseDate(value);
  return d ? dayFmt.format(d) : "";
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

export function formatRelative(value: unknown, now = Date.now()): string {
  const d = parseDate(value);
  if (!d) return "";
  const seconds = Math.round((d.getTime() - now) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return seconds <= 0 ? "just now" : "in a few seconds";
  for (const [unit, size] of UNITS) {
    if (abs >= size) return rtf.format(Math.round(seconds / size), unit);
  }
  return rtf.format(Math.round(seconds / 60), "minute");
}

export function utcLabel(value: unknown): string {
  const d = parseDate(value);
  return d ? `${d.toISOString().replace("T", " ").slice(0, 19)} UTC` : "";
}

export function formatPercent(fraction: number | null | undefined, digits = 0): string {
  if (fraction === null || fraction === undefined || Number.isNaN(fraction)) return "Unavailable";
  return `${(fraction * 100).toFixed(digits)}%`;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${Math.round(s % 60)} s`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function humanize(value: string | null | undefined): string {
  if (!value) return "";
  const s = value.replace(/[_-]+/g, " ").trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}
