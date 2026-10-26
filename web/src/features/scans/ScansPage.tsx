import { Button, Select, Table, Text } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconRadar } from "@tabler/icons-react";
import { useEffect, useMemo } from "react";
import { useSearchParams } from "react-router";
import type { ScansQuery } from "../../api/types";
import { DemoBadge, DemoBanner, isFixture } from "../../components/DemoData";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { RowLink } from "../../components/RowLink";
import { StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { formatDuration, formatPercent, humanize } from "../../lib/format";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "../devices/api";
import { useScans } from "./api";
import { NewScanDialog } from "./NewScanDialog";
import classes from "./Scans.module.css";

const STATUS_OPTIONS = ["queued", "running", "completed", "partial", "failed", "cancelled"];
const TYPE_OPTIONS = ["full", "posture", "inventory", "logs", "network", "malware", "custom"];

function durationMs(start: string | null, end: string | null): number | null {
  if (!start || !end) return null;
  return new Date(end).getTime() - new Date(start).getTime();
}

export function ScansPage() {
  const [params, setParams] = useSearchParams();
  const { deviceId: scopeDevice } = useDeviceScope();
  const devices = useDevices(true);
  const [dialogOpen, dialog] = useDisclosure(params.get("new") === "1");

  // Filters live in the URL so a filtered view can be bookmarked and survives reloads.
  const device = params.get("device") ?? (scopeDevice !== null ? String(scopeDevice) : null);
  const status = params.get("status");
  const type = params.get("type");
  const limit = Number(params.get("limit") ?? 25);
  const offset = Number(params.get("offset") ?? 0);

  useEffect(() => {
    if (params.get("new") === "1") {
      dialog.open();
      const next = new URLSearchParams(params);
      next.delete("new");
      setParams(next, { replace: true });
    }
  }, [params, setParams, dialog]);

  const query: ScansQuery = {
    device_id: device ? Number(device) : undefined,
    status: status ?? undefined,
    scan_type: type ?? undefined,
    limit,
    offset,
  };
  const scans = useScans(query);
  const names = useMemo(() => new Map((devices.data ?? []).map((d) => [d.id, d.name])), [devices.data]);
  const anyFixture = scans.data?.items.some((s) => isFixture(s.data_mode));

  const setFilter = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("offset");
    setParams(next, { replace: true });
  };

  return (
    <>
      <PageHeader
        title="Security scans"
        description="Every scan requested, with what ran, what was skipped and why."
        actions={
          <Button leftSection={<IconRadar size={16} />} onClick={dialog.open}>
            New scan
          </Button>
        }
      />
      {anyFixture ? <DemoBanner>Some scans in this list used fixture (demo) data, not live data from a device.</DemoBanner> : null}
      <Panel padded={false}>
        <div className={classes.filters} role="search" aria-label="Filter scans">
          <Select
            size="xs"
            w={200}
            label="Device"
            data={[
              { value: "", label: "All devices" },
              ...(devices.data ?? []).map((d) => ({
                value: String(d.id),
                label: d.is_active ? d.name : `${d.name} (revoked)`,
              })),
            ]}
            value={device ?? ""}
            onChange={(v) => setFilter("device", v || null)}
          />
          <Select
            size="xs"
            w={150}
            label="Status"
            data={[{ value: "", label: "Any status" }, ...STATUS_OPTIONS.map((s) => ({ value: s, label: humanize(s) }))]}
            value={status ?? ""}
            onChange={(v) => setFilter("status", v || null)}
          />
          <Select
            size="xs"
            w={150}
            label="Type"
            data={[{ value: "", label: "Any type" }, ...TYPE_OPTIONS.map((s) => ({ value: s, label: humanize(s) }))]}
            value={type ?? ""}
            onChange={(v) => setFilter("type", v || null)}
          />
        </div>
        {scans.isPending ? <Loading label="Loading scans" /> : null}
        {scans.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorState error={scans.error} onRetry={() => void scans.refetch()} />
          </div>
        ) : null}
        {scans.data && scans.data.items.length === 0 ? (
          <Empty
            title={status || type || device ? "No scans match these filters" : "No scans yet"}
            action={
              <Button variant="default" onClick={dialog.open}>
                New scan
              </Button>
            }
          >
            {status || type || device
              ? "Clear a filter to see more."
              : "Start a scan to see what Sentinel checks. A full scan takes a minute or two."}
          </Empty>
        ) : null}
        {scans.data && scans.data.items.length > 0 ? (
          <>
            <div className={classes.tableWrap}>
              <Table miw={900} stickyHeader>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Scan</Table.Th>
                    <Table.Th>Device</Table.Th>
                    <Table.Th>Type</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Requested</Table.Th>
                    <Table.Th>Duration</Table.Th>
                    <Table.Th>Score</Table.Th>
                    <Table.Th>Coverage</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {scans.data.items.map((s) => (
                    <Table.Tr key={s.id}>
                      <Table.Td>
                        <RowLink to={`/scans/${s.id}`}>Scan {s.id}</RowLink>
                        {isFixture(s.data_mode) ? (
                          <div style={{ marginTop: 4 }}>
                            <DemoBadge />
                          </div>
                        ) : null}
                      </Table.Td>
                      <Table.Td>{names.get(s.device_id) ?? `Device ${s.device_id}`}</Table.Td>
                      <Table.Td>
                        <Tag>{humanize(s.scan_type)}</Tag>
                        {s.elevated ? (
                          <Text size="xs" c="dimmed" mt={3}>
                            Elevated
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td>
                        <StatusBadge kind="scan" value={s.status} />
                        {s.cancel_requested && s.status === "running" ? (
                          <Text size="xs" c="dimmed" mt={3}>
                            Cancelling
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td>
                        <Time value={s.requested_at} />
                        {s.reason && s.reason !== "manual" ? (
                          <Text size="xs" c="dimmed" mt={2}>
                            {humanize(s.reason)}
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td className="sn-num">
                        {formatDuration(durationMs(s.started_at, s.completed_at)) || <span className="sn-dim">–</span>}
                      </Table.Td>
                      <Table.Td className="sn-num">
                        {s.score !== null ? (
                          s.score
                        ) : s.completed_at && (s.scan_type === "full" || s.scan_type === "posture") ? (
                          <span className="sn-dim">Incomplete</span>
                        ) : (
                          <span className="sn-dim">–</span>
                        )}
                      </Table.Td>
                      <Table.Td className="sn-num">
                        {s.coverage !== null ? formatPercent(s.coverage) : <span className="sn-dim">–</span>}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </div>
            <Pager
              total={scans.data.total}
              limit={limit}
              offset={offset}
              onChange={(p) => {
                const next = new URLSearchParams(params);
                next.set("limit", String(p.limit));
                next.set("offset", String(p.offset));
                setParams(next, { replace: true });
              }}
            />
          </>
        ) : null}
      </Panel>
      <NewScanDialog
        opened={dialogOpen}
        onClose={dialog.close}
        initialDeviceId={device ? Number(device) : scopeDevice}
      />
    </>
  );
}
