import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, apiRequest, buildUrl, formatDetail, setCsrfToken, setUnauthorizedHandler } from "./client";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("api client", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("csrf-abc");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    setCsrfToken(null);
    setUnauthorizedHandler(null);
  });

  function headersOf(call: number): Headers {
    const init = fetchMock.mock.calls[call][1];
    return new Headers(init?.headers);
  }

  it("sends the CSRF header on every state-changing method", async () => {
    fetchMock.mockImplementation(async () => jsonResponse(200, { ok: true }));
    await api.post("/api/scans", { device_id: 1 });
    await api.patch("/api/findings/1", { note: "x" });
    await api.put("/api/settings/retention", { metric_days: 30 });
    await api.del("/api/secrets/nvd_api_key");
    for (let i = 0; i < 4; i++) {
      expect(headersOf(i).get("X-CSRF-Token")).toBe("csrf-abc");
      expect(fetchMock.mock.calls[i][1]?.credentials).toBe("same-origin");
    }
    expect(fetchMock.mock.calls.map((c) => c[1]?.method)).toEqual(["POST", "PATCH", "PUT", "DELETE"]);
  });

  it("does not send the CSRF header on GET", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { items: [], total: 0 }));
    await api.get("/api/scans", { limit: 10 });
    expect(headersOf(0).get("X-CSRF-Token")).toBeNull();
    expect(fetchMock.mock.calls[0][1]?.credentials).toBe("same-origin");
  });

  it("calls the unauthorized handler on 401 and throws a readable error", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    fetchMock.mockResolvedValue(jsonResponse(401, { detail: "Session expired" }));
    const err = await apiRequest("/api/dashboard/overview").catch((e: unknown) => e);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(401);
    expect((err as ApiError).message).toBe("Session expired");
  });

  it("does not treat a failed sign-in as an ended session", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    fetchMock.mockResolvedValue(jsonResponse(401, { detail: "Wrong username or password" }));
    await expect(api.post("/api/auth/login", { username: "a", password: "b" }, { ignoreUnauthorized: true })).rejects.toThrow(
      "Wrong username or password",
    );
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("turns FastAPI validation details into one sentence", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(422, { detail: [{ loc: ["body", "target_date"], msg: "String should match pattern" }] }),
    );
    await expect(api.patch("/api/findings/3", { target_date: "x" })).rejects.toThrow("target date: String should match pattern");
    expect(formatDetail("  ")).toBeNull();
  });

  it("explains a network failure instead of surfacing a TypeError", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    await expect(api.get("/api/devices")).rejects.toThrow(/Can't reach the Sentinel server/);
  });

  it("returns undefined for 204 responses", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(api.del("/api/devices/1")).resolves.toBeUndefined();
  });

  it("builds query strings with repeated keys and skips empty values", () => {
    expect(buildUrl("/api/findings", { severity: ["high", "critical"], q: "", device_id: null, kev: true })).toBe(
      "/api/findings?severity=high&severity=critical&kev=true",
    );
  });
});
