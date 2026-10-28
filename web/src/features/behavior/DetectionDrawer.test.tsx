import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DetectionDetail } from "../../api/types";
import { setCsrfToken } from "../../api/client";
import { renderUi } from "../../test/render";
import { DetectionDrawer } from "./BehaviorPage";

function makeDetail(overrides: Partial<DetectionDetail> = {}): DetectionDetail {
  return {
    id: 1,
    device_id: 7,
    rule_id: "intrusion.suspicious_exec_chain",
    title: "Suspicious execution chain reached out",
    summary: "winword.exe launched powershell.exe, which connected to an external host.",
    severity: "critical",
    confidence: "high",
    technique_ids: ["T1059"],
    technique_names: ["Command and Scripting Interpreter"],
    host: "WIN-ACCT-04",
    first_ts: "2026-10-28T09:00:00Z",
    last_ts: "2026-10-28T09:05:00Z",
    count: 2,
    status: "new",
    created_at: "2026-10-28T09:05:00Z",
    explanation: "An Office document spawned PowerShell.\nThat PowerShell then connected outbound.",
    process_guids: ["P", "W"],
    process_tree: [
      { process_guid: "P", pid: 4242, image: "C:\\Windows\\powershell.exe", command_line: "powershell -enc AAA" },
      { process_guid: "W", pid: 100, image: "C:\\Office\\winword.exe" },
    ],
    events: [
      { kind: "process_create", image: "C:\\Windows\\powershell.exe", parent_image: "C:\\Office\\winword.exe", command_line: "powershell -enc AAA", ts: "2026-10-28T09:00:00Z" },
      { kind: "network_connect", image: "C:\\Windows\\powershell.exe", dest_ip: "8.8.8.8", dest_port: 443, protocol: "tcp", direction: "outbound", ts: "2026-10-28T09:05:00Z" },
    ],
    ...overrides,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("DetectionDrawer", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("csrf-abc");
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    setCsrfToken(null);
  });

  it("renders the process tree and the triggering events from the detail", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, makeDetail()));
    renderUi(<DetectionDrawer id={1} onClose={vi.fn()} />);

    // process tree (ancestry, nearest first): image basenames, pid and command line
    expect(await screen.findByText("powershell.exe")).toBeInTheDocument();
    expect(screen.getByText("winword.exe")).toBeInTheDocument();
    expect(screen.getByText("pid 4242")).toBeInTheDocument();
    expect(screen.getAllByText("powershell -enc AAA").length).toBeGreaterThan(0);

    // triggering events rendered as readable rows with a human summary
    expect(screen.getByText("Network connection")).toBeInTheDocument();
    expect(screen.getByText("powershell.exe → 8.8.8.8:443 (outbound tcp)")).toBeInTheDocument();

    // the explanation keeps its line breaks (pre-wrap), not dumped as a single run
    expect(screen.getByText(/An Office document spawned PowerShell\./)).toBeInTheDocument();
  });

  it("fires a PATCH with status=acknowledged when Acknowledge is clicked", async () => {
    fetchMock.mockImplementation(async (_url, init) => {
      if (init?.method === "PATCH") return jsonResponse(200, makeDetail({ status: "acknowledged" }));
      return jsonResponse(200, makeDetail());
    });
    const user = userEvent.setup();
    renderUi(<DetectionDrawer id={1} onClose={vi.fn()} />);

    const ack = await screen.findByRole("button", { name: "Acknowledge" });
    await user.click(ack);

    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH");
      expect(patch).toBeDefined();
      expect(String(patch![0])).toBe("/api/behavior/detections/1");
      expect(JSON.parse(String(patch![1]?.body))).toEqual({ status: "acknowledged" });
    });
  });

  it("fires a PATCH with status=dismissed when Dismiss is clicked", async () => {
    fetchMock.mockImplementation(async (_url, init) => {
      if (init?.method === "PATCH") return jsonResponse(200, makeDetail({ status: "dismissed" }));
      return jsonResponse(200, makeDetail());
    });
    const user = userEvent.setup();
    renderUi(<DetectionDrawer id={1} onClose={vi.fn()} />);

    await user.click(await screen.findByRole("button", { name: "Dismiss" }));

    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH");
      expect(patch).toBeDefined();
      expect(JSON.parse(String(patch![1]?.body))).toEqual({ status: "dismissed" });
    });
  });

  it("reflects the current status: Acknowledge is disabled once already acknowledged", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, makeDetail({ status: "acknowledged" })));
    renderUi(<DetectionDrawer id={1} onClose={vi.fn()} />);
    expect(await screen.findByRole("button", { name: "Acknowledge" })).toBeDisabled();
  });
});
