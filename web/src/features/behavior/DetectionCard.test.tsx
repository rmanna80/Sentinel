import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { DetectionOut } from "../../api/types";
import { renderUi } from "../../test/render";
import { DetectionCard } from "./DetectionCard";

function makeDetection(overrides: Partial<DetectionOut> = {}): DetectionOut {
  return {
    id: 1,
    device_id: 7,
    rule_id: "intrusion.suspicious_exec_chain",
    title: "Office app spawned an interpreter that called out",
    summary: "winword.exe launched powershell.exe, which connected to an external host.",
    severity: "critical",
    confidence: "high",
    technique_ids: ["T1059", "T1566"],
    technique_names: ["Command and Scripting Interpreter", "Phishing"],
    host: "WIN-ACCT-04",
    first_ts: "2026-10-28T09:00:00Z",
    last_ts: "2026-10-28T09:05:00Z",
    count: 1,
    status: "new",
    created_at: "2026-10-28T09:05:00Z",
    ...overrides,
  };
}

describe("DetectionCard", () => {
  it("shows the severity as a labelled chip, not color alone", () => {
    renderUi(<DetectionCard detection={makeDetection({ severity: "critical" })} onOpen={vi.fn()} />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("renders the rule id in mono and each ATT&CK technique id with its name as the label", () => {
    renderUi(<DetectionCard detection={makeDetection()} onOpen={vi.fn()} />);
    expect(screen.getByText("intrusion.suspicious_exec_chain")).toBeInTheDocument();
    expect(screen.getByText("T1059")).toBeInTheDocument();
    expect(screen.getByText("T1566")).toBeInTheDocument();
    // the technique name travels as the accessible label / tooltip, not just color.
    expect(screen.getByLabelText("ATT&CK T1059: Command and Scripting Interpreter")).toBeInTheDocument();
  });

  it("shows a repeat-count badge only when the behaviour was seen more than once", () => {
    const { rerender } = renderUi(<DetectionCard detection={makeDetection({ count: 1 })} onOpen={vi.fn()} />);
    expect(screen.queryByText("1×")).toBeNull();
    rerender(<DetectionCard detection={makeDetection({ count: 4 })} onOpen={vi.fn()} />);
    expect(screen.getByText("4×")).toBeInTheDocument();
  });

  it("opens the evidence drawer when the row body is activated", () => {
    const onOpen = vi.fn();
    const { getByRole } = renderUi(<DetectionCard detection={makeDetection()} onOpen={onOpen} />);
    getByRole("button", { name: /Open detection: Office app spawned an interpreter/ }).click();
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});
