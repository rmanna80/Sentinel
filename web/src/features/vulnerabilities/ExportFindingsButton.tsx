import { Button, Menu } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDownload } from "@tabler/icons-react";
import { useState } from "react";
import { downloadFile, errorMessage } from "../../api/client";
import type { ExportFindingsQuery, FindingsQuery } from "../../api/types";

/** Exports the findings that match the current filters (status, severity, device, category, source). */
export function ExportFindingsButton({ query }: { query: FindingsQuery }) {
  const [busy, setBusy] = useState(false);
  const run = async (format: "csv" | "json") => {
    setBusy(true);
    const q: ExportFindingsQuery = {
      format,
      status: query.status,
      severity: query.severity ?? undefined,
      device_id: query.device_id ?? undefined,
      category: query.category ?? undefined,
      source: query.source ?? undefined,
    };
    try {
      await downloadFile("/api/export/findings", q, `sentinel-findings.${format}`);
    } catch (err) {
      notifications.show({ color: "red", title: "Export failed", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Menu position="bottom-end">
      <Menu.Target>
        <Button size="xs" variant="default" leftSection={<IconDownload size={14} />} loading={busy}>
          Export
        </Button>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Matching findings (search and kind filters aren't applied)</Menu.Label>
        <Menu.Item onClick={() => void run("csv")}>CSV</Menu.Item>
        <Menu.Item onClick={() => void run("json")}>JSON</Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
