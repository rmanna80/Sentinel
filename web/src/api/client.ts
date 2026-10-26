/**
 * The one way the dashboard talks to the server.
 *
 * - Cookies are same-origin only (the session cookie is HttpOnly; JavaScript never sees it).
 * - Every state-changing request carries the X-CSRF-Token header from /api/auth/state.
 * - Errors become ApiError with a readable message built from the server's {detail}.
 * - A 401 tells the auth layer the session ended, so the app returns to the sign-in screen.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, message: string, detail: unknown = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export type QueryValue = string | number | boolean | null | undefined | ReadonlyArray<string | number>;
export type Query = Record<string, QueryValue>;
export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface RequestOptions {
  method?: Method;
  query?: Query;
  body?: unknown;
  signal?: AbortSignal;
  /** Sign-in and setup answer wrong credentials with 401; that must not count as "session ended". */
  ignoreUnauthorized?: boolean;
}

export const CSRF_HEADER = "X-CSRF-Token";
const SAFE_METHODS = new Set<Method>(["GET"]);

let csrfToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function setCsrfToken(token: string | null | undefined): void {
  csrfToken = token ?? null;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

/** Register what happens when the server says the session is gone (one handler at a time). */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

export function buildUrl(path: string, query?: Query): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) params.append(key, String(item));
    } else {
      params.append(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

interface ValidationIssue {
  loc?: unknown;
  msg?: unknown;
}

function isIssue(value: unknown): value is ValidationIssue {
  return typeof value === "object" && value !== null && "msg" in value;
}

/** Turn FastAPI's `detail` (a string, or a list of validation issues) into one readable sentence. */
export function formatDetail(detail: unknown): string | null {
  if (typeof detail === "string") return detail.trim() || null;
  if (Array.isArray(detail)) {
    const parts = detail.filter(isIssue).map((issue) => {
      const loc = Array.isArray(issue.loc)
        ? issue.loc.filter((p) => p !== "body" && p !== "query" && p !== "path").map(String).join(".")
        : "";
      const msg = String(issue.msg);
      return loc ? `${loc.replace(/_/g, " ")}: ${msg}` : msg;
    });
    return parts.length ? parts.join("; ") : null;
  }
  return null;
}

function fallbackMessage(status: number): string {
  if (status === 401) return "You are signed out. Sign in again to continue.";
  if (status === 403) return "The server refused this request.";
  if (status === 404) return "Not found. It may have been removed.";
  if (status === 409) return "This conflicts with the current state. Reload and try again.";
  if (status === 421) return "The server rejected the address used to reach it. Open Sentinel at http://127.0.0.1.";
  if (status === 429) return "Too many attempts. Wait a minute, then try again.";
  if (status >= 500) return `The server hit an error (HTTP ${status}). The server console has the details.`;
  return `The request failed (HTTP ${status}).`;
}

async function readError(res: Response): Promise<ApiError> {
  let detail: unknown = null;
  try {
    const body: unknown = await res.json();
    if (typeof body === "object" && body !== null && "detail" in body) {
      detail = (body as { detail: unknown }).detail;
    }
  } catch {
    // not JSON; fall back to the status text below
  }
  return new ApiError(res.status, formatDetail(detail) ?? fallbackMessage(res.status), detail);
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: string | undefined;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  if (!SAFE_METHODS.has(method) && csrfToken) {
    headers[CSRF_HEADER] = csrfToken;
  }

  let res: Response;
  try {
    res = await fetch(buildUrl(path, options.query), {
      method,
      headers,
      body,
      credentials: "same-origin",
      signal: options.signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(0, "Can't reach the Sentinel server. Check that it is running, then try again.");
  }

  if (res.status === 401 && !options.ignoreUnauthorized) {
    unauthorizedHandler?.();
  }
  if (!res.ok) throw await readError(res);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const api = {
  get: <T>(path: string, query?: Query, signal?: AbortSignal) => apiRequest<T>(path, { query, signal }),
  post: <T>(path: string, body?: unknown, extra?: Omit<RequestOptions, "method" | "body">) =>
    apiRequest<T>(path, { ...extra, method: "POST", body }),
  put: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "PUT", body }),
  patch: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "PATCH", body }),
  del: (path: string) => apiRequest<void>(path, { method: "DELETE" }),
};

export function isApiError(err: unknown, status?: number): err is ApiError {
  return err instanceof ApiError && (status === undefined || err.status === status);
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError || err instanceof Error) return err.message;
  return "Something went wrong.";
}

function filenameFrom(disposition: string | null, fallback: string): string {
  if (!disposition) return fallback;
  const star = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(disposition);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim().replace(/^"|"$/g, ""));
    } catch {
      // fall through to the plain filename
    }
  }
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(disposition);
  return plain ? plain[1].trim() : fallback;
}

/**
 * Download a file the server generates (reports, exports). Fetching (rather than navigating) keeps the
 * session-ended and error handling the same as every other request.
 */
export async function downloadFile(path: string, query: Query | undefined, fallbackName: string): Promise<string> {
  let res: Response;
  try {
    res = await fetch(buildUrl(path, query), { credentials: "same-origin", headers: { Accept: "*/*" } });
  } catch {
    throw new ApiError(0, "Can't reach the Sentinel server. Check that it is running, then try again.");
  }
  if (res.status === 401) unauthorizedHandler?.();
  if (!res.ok) throw await readError(res);
  const blob = await res.blob();
  const name = filenameFrom(res.headers.get("Content-Disposition"), fallbackName);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  return name;
}
