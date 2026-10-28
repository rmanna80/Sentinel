import { describe, expect, it } from "vitest";
import { basename, detectionEvents, eventSummary, processAncestry } from "./evidence";

describe("basename", () => {
  it("takes the last segment of a Windows or POSIX path", () => {
    expect(basename("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")).toBe("powershell.exe");
    expect(basename("/usr/bin/curl")).toBe("curl");
    expect(basename(null)).toBe("");
  });
});

describe("eventSummary", () => {
  it("summarises a process_create as parent -> child with its command line", () => {
    expect(
      eventSummary({
        kind: "process_create",
        image: "C:\\Windows\\powershell.exe",
        parent_image: "C:\\Office\\winword.exe",
        command_line: "powershell -enc AAA",
      }),
    ).toBe("winword.exe → powershell.exe · powershell -enc AAA");
  });

  it("summarises a network_connect as actor -> host:port with direction/protocol", () => {
    expect(
      eventSummary({
        kind: "network_connect",
        image: "C:\\Windows\\powershell.exe",
        dest_ip: "8.8.8.8",
        dest_port: 443,
        protocol: "tcp",
        direction: "outbound",
      }),
    ).toBe("powershell.exe → 8.8.8.8:443 (outbound tcp)");
  });

  it("summarises a registry_set with the key and value", () => {
    expect(
      eventSummary({
        kind: "registry_set",
        image: "C:\\Windows\\powershell.exe",
        registry_path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        registry_value: "Updater",
      }),
    ).toBe("powershell.exe set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater");
  });

  it("summarises a file_write with the path", () => {
    expect(eventSummary({ kind: "file_write", image: "C:\\a\\b.exe", file_path: "C:\\Temp\\x.dll" })).toBe(
      "b.exe wrote C:\\Temp\\x.dll",
    );
  });
});

describe("processAncestry and detectionEvents", () => {
  it("reads process nodes nearest-first and tolerates missing fields", () => {
    const nodes = processAncestry([
      { process_guid: "P", pid: 42, image: "C:\\Windows\\powershell.exe", command_line: "powershell -enc AAA" },
      { process_guid: "W", pid: 7, image: "C:\\Office\\winword.exe" },
      "garbage" as unknown as Record<string, unknown>,
    ]);
    expect(nodes).toHaveLength(3);
    expect(nodes[0]).toMatchObject({ processGuid: "P", pid: 42, image: "C:\\Windows\\powershell.exe" });
    expect(nodes[1].commandLine).toBeNull();
  });

  it("maps events to a kind label and summary", () => {
    const rows = detectionEvents([
      { kind: "network_connect", image: "C:\\p.exe", dest_ip: "1.2.3.4", dest_port: 80, ts: "2026-10-28T09:00:00Z" },
    ]);
    expect(rows[0].kindLabel).toBe("Network connection");
    expect(rows[0].summary).toBe("p.exe → 1.2.3.4:80");
    expect(rows[0].ts).toBe("2026-10-28T09:00:00Z");
  });

  it("returns an empty list for a non-array blob", () => {
    expect(processAncestry(undefined)).toEqual([]);
    expect(detectionEvents(null)).toEqual([]);
  });
});
