import { describe, expect, it } from "vitest";
import { buildUrl } from "../../api/client";
import { buildDetectionsQuery } from "./api";

const base = { limit: 50, offset: 0 };

describe("buildDetectionsQuery", () => {
  it("omits the status param in the default view (new + acknowledged)", () => {
    const q = buildDetectionsQuery({ ...base, status: "open" });
    expect(q.status).toBeUndefined();
    // and so no status appears on the wire, which is how the server hides dismissed by default.
    expect(buildUrl("/api/behavior/detections", q)).toBe("/api/behavior/detections?limit=50&offset=0");
  });

  it("sends status=dismissed when the Dismissed filter is chosen", () => {
    const q = buildDetectionsQuery({ ...base, status: "dismissed" });
    expect(q.status).toBe("dismissed");
    expect(buildUrl("/api/behavior/detections", q)).toContain("status=dismissed");
  });

  it("passes status=all through to show everything", () => {
    expect(buildDetectionsQuery({ ...base, status: "all" }).status).toBe("all");
  });

  it("drops blank severity, host and search but keeps real values", () => {
    expect(buildDetectionsQuery({ ...base, status: "open", severity: "", host: "", q: "  " })).toMatchObject({
      status: undefined,
      severity: undefined,
      host: undefined,
      q: undefined,
    });
    expect(buildDetectionsQuery({ ...base, status: "new", severity: "high", host: "WIN-1", q: " ps " })).toMatchObject({
      status: "new",
      severity: "high",
      host: "WIN-1",
      q: "ps",
    });
  });
});
