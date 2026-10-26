import { describe, expect, it } from "vitest";
import { citationHref, parseCitations } from "./citations";

describe("assistant citations", () => {
  it("splits plain text from citation groups", () => {
    const segs = parseCitations("Firewall is off [finding:12, 13] seen in [scan:4; event:9]. <b>not html</b>");
    expect(segs).toEqual([
      { kind: "text", text: "Firewall is off " },
      { kind: "cite", raw: "[finding:12, 13]", refs: [{ type: "finding", id: "12" }, { type: "finding", id: "13" }] },
      { kind: "text", text: " seen in " },
      { kind: "cite", raw: "[scan:4; event:9]", refs: [{ type: "scan", id: "4" }, { type: "event", id: "9" }] },
      { kind: "text", text: ". <b>not html</b>" },
    ]);
  });

  it("maps citations to dashboard links", () => {
    expect(citationHref({ type: "finding", id: "12" })).toBe("/vulnerabilities/12");
    expect(citationHref({ type: "alert", id: "3" })).toBe("/threats/alerts/3");
    expect(citationHref({ type: "event", id: "9" })).toBe("/logs?event=9");
    expect(citationHref({ type: "scan", id: "x" })).toBeNull();
  });
});
