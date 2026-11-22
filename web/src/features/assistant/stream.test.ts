import { describe, expect, it } from "vitest";
import { applyStreamEvent, EMPTY_PROGRESS } from "./api";

describe("applyStreamEvent", () => {
  it("builds the answer from deltas and counts the tools that ran", () => {
    const events = [
      { type: "round", round: 1 },
      { type: "delta", text: "Let me look." },
      { type: "reset" },
      { type: "tool", name: "get_finding", ok: true },
      { type: "round", round: 2 },
      { type: "delta", text: "The firewall " },
      { type: "delta", text: "is off." },
    ];
    const progress = events.reduce(applyStreamEvent, EMPTY_PROGRESS);
    expect(progress).toEqual({ text: "The firewall is off.", tools: ["get_finding"] });
  });

  it("ignores events it does not understand", () => {
    for (const event of [null, "text", 7, {}, { type: "delta" }, { type: "tool", name: 3 }, { type: "new-thing" }]) {
      expect(applyStreamEvent(EMPTY_PROGRESS, event)).toBe(EMPTY_PROGRESS);
    }
  });
});
