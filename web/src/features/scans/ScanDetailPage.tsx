import { Alert, Anchor, Button, Group, Modal, Progress, Select, Table, Text, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle, IconArrowsDiff, IconDownload, IconPlayerStop, IconShieldLock } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { CheckRunOut, FindingOut, ScanDetail } from "../../api/types";
import { CommandBox } from "../../components/CommandBox";
import { DemoBanner, isFixture } from "../../components/DemoData";
import { Facts } from "../../components/Facts";
import { JsonView } from "../../components/JsonView";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { RowLink } from "../../components/RowLink";
import { SeverityBadge } from "../../components/Severity";
import { StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { saveJson } from "../../lib/download";
import { formatDuration, formatPercent, formatShort, humanize, plural } from "../../lib/format";
import { useDevice } from "../devices/api";
import { ACTIVE_SCAN, fetchScanExport, useCancelScan, useScan, useScanDiff, useScans } from "./api";
import classes from "./Scans.module.css";

const RUN_ORDER = ["failed", "error", "timeout", "skipped", "planned", "passed", "not_applicable", "cancelled"];

export function ScanDetailPage() {
  const id = Number(useParams().scanId);
  const scan = useScan(id);
  if (!Number.isInteger(id) || id <= 0) return <ErrorState error={new Error("That scan link isn't valid.")} />;
  if (scan.isPending) return <Loading label="Loading scan" />;
  if (scan.isError) return <ErrorState error={scan.error} onRetry={() => void scan.refetch()} />;
  return <ScanDetailBody scan={scan.data} />;
}

function ScanDetailBody({ scan }: { scan: ScanDetail }) {
  const device = useDevice(scan.device_id);
  const cancel = useCancelScan(scan.id);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [compareOpen, setCompareOpen] = useState(false);
  const active = ACTIVE_SCAN.has(scan.status);
  const deviceName = device.data?.name ?? `Device ${scan.device_id}`;

  const doExport = async () => {
    setExporting(true);
    try {
      const data = await fetchScanExport(scan.id);
      saveJson(data, `sentinel-scan-${scan.id}.json`);
    } catch (err) {
      notifications.show({ color: "red", title: "Export failed", message: errorMessage(err) });
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <PageHeader
        title={`${humanize(scan.scan_type)} scan ${scan.id}`}
        docTitle={`Scan ${scan.id}`}
        meta={
          <>
            <StatusBadge kind="scan" value={scan.status} />
            <span>
              <Link to={`/devices/${scan.device_id}`} className="sn-link">
                {deviceName}
              </Link>
            </span>
            <span>
              Requested <Time value={scan.requested_at} />
            </span>
            {scan.elevated ? <Tag tone="warn">Elevated</Tag> : null}
            {scan.reason && scan.reason !== "manual" ? <Tag>{humanize(scan.reason)}</Tag> : null}
          </>
        }
        actions={
          <>
            {active ? (
              <Button
                variant="default"
                color="red"
                leftSection={<IconPlayerStop size={16} />}
                onClick={() => setConfirmCancel(true)}
                disabled={scan.cancel_requested}
              >
                {scan.cancel_requested ? "Cancelling" : "Cancel scan"}
              </Button>
            ) : null}
            <Button
              variant="default"
              leftSection={<IconArrowsDiff size={16} />}
              onClick={() => setCompareOpen((o) => !o)}
              disabled={active}
              aria-expanded={compareOpen}
            >
              Compare
            </Button>
            <Button variant="default" leftSection={<IconDownload size={16} />} onClick={doExport} loading={exporting}>
              Export JSON
            </Button>
          </>
        }
      />

      {isFixture(scan.data_mode) ? (
        <DemoBanner>
          This scan answered from a fixture file (recorded sample output), not from the device itself. Its findings are
          for learning the dashboard.
        </DemoBanner>
      ) : null}

      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {scan.status === "queued" && scan.elevated ? (
          <Alert variant="light" color="iris" icon={<IconShieldLock size={18} />} title="Waiting for an administrator to start it">
            <Text size="sm" mb="xs">
              On {deviceName}, run this in PowerShell. Windows asks for permission; the agent runs this one scan read-only,
              then exits.
            </Text>
            <CommandBox command="scripts\elevated-scan.ps1" label="PowerShell" />
          </Alert>
        ) : null}
        {scan.error ? (
          <Alert color="red" variant="light" icon={<IconAlertCircle size={18} />} title="The scan reported an error">
            {scan.error}
          </Alert>
        ) : null}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
          <Panel title={active ? "Progress" : "Result"}>
            <ScanProgress scan={scan} />
          </Panel>
          <Panel title="Details">
            <Facts
              items={[
                ["Started", <Time key="s" value={scan.started_at} empty="Not started" />],
                ["Completed", <Time key="c" value={scan.completed_at} empty={active ? "In progress" : "–"} />],
                [
                  "Score",
                  scan.score !== null ? (
                    <strong key="sc">{scan.score}</strong>
                  ) : scan.scan_type === "full" || scan.scan_type === "posture" ? (
                    <span key="sc" className="sn-dim">
                      {active ? "After it completes" : "Incomplete: too few checks completed"}
                    </span>
                  ) : (
                    <span key="sc" className="sn-dim">
                      Not scored ({humanize(scan.scan_type).toLowerCase()} scans don't set the score)
                    </span>
                  ),
                ],
                ["Coverage", scan.coverage !== null ? formatPercent(scan.coverage) : <span className="sn-dim">–</span>],
                ["Data", isFixture(scan.data_mode) ? "Fixture (demo)" : "Live from the device"],
              ]}
            />
          </Panel>
        </div>

        {compareOpen ? <ComparePanel scan={scan} /> : null}

        <Panel
          title="Checks"
          description="A check that passed means that one condition wasn't observed; it doesn't mean the device is secure."
          padded={false}
        >
          <CheckRunsTable runs={scan.check_runs} active={active} />
        </Panel>

        {scan.host_snapshot ? (
          <Panel title="Host snapshot" description="What the agent reported about the device when the scan ran.">
            <JsonView value={scan.host_snapshot} maxHeight={280} />
          </Panel>
        ) : null}
      </div>

      <Modal opened={confirmCancel} onClose={() => setConfirmCancel(false)} title="Cancel this scan?" size="sm">
        <Text size="sm">
          {scan.status === "queued"
            ? "It hasn't started, so it's removed from the queue."
            : "The agent stops after the check it's running now. Results already uploaded are kept."}
        </Text>
        {cancel.isError ? (
          <Text size="sm" c="red" mt="sm" role="alert">
            {errorMessage(cancel.error)}
          </Text>
        ) : null}
        <Group justify="flex-end" mt="md">
          <Button variant="default" onClick={() => setConfirmCancel(false)}>
            Keep scanning
          </Button>
          <Button
            color="red"
            loading={cancel.isPending}
            onClick={() => cancel.mutate(undefined, { onSuccess: () => setConfirmCancel(false) })}
          >
            Cancel scan
          </Button>
        </Group>
      </Modal>
    </>
  );
}

function ScanProgress({ scan }: { scan: ScanDetail }) {
  const p = scan.progress;
  const total = p.total ?? 0;
  const done = p.done ?? 0;
  const pct = total ? (done / total) * 100 : 0;
  const active = ACTIVE_SCAN.has(scan.status);
  const parts: [string, number][] = [
    ["passed", p.passed ?? 0],
    ["issue found", p.failed ?? 0],
    ["skipped", p.skipped ?? 0],
    ["not applicable", p.not_applicable ?? 0],
    ["errors", (p.error ?? 0) + (p.timeout ?? 0)],
    ["waiting", p.planned ?? 0],
  ];
  return (
    <div className={classes.progress} aria-live={active ? "polite" : undefined}>
      <div className={classes.progressHead}>
        <span>
          {scan.status === "queued"
            ? "Waiting for the agent"
            : total
              ? `${done} of ${plural(total, "check")} finished`
              : active
                ? "Planning checks"
                : "No checks ran"}
        </span>
        {total ? <span className="sn-num">{Math.round(pct)}%</span> : null}
      </div>
      <Progress
        value={scan.status === "queued" ? 0 : pct}
        animated={scan.status === "running"}
        striped={scan.status === "running"}
        aria-label="Scan progress"
        size="md"
      />
      <div className={classes.counts}>
        {parts
          .filter(([, n]) => n > 0)
          .map(([label, n]) => (
            <span key={label}>
              <strong>{n}</strong> {label}
            </span>
          ))}
      </div>
      {active ? (
        <Text size="xs" c="dimmed">
          Updates every two seconds while the scan runs.
        </Text>
      ) : null}
    </div>
  );
}

function CheckRunsTable({ runs, active }: { runs: CheckRunOut[]; active: boolean }) {
  const sorted = useMemo(
    () =>
      [...runs].sort(
        (a, b) =>
          RUN_ORDER.indexOf(a.status) - RUN_ORDER.indexOf(b.status) ||
          a.category.localeCompare(b.category) ||
          a.title.localeCompare(b.title),
      ),
    [runs],
  );
  if (runs.length === 0) {
    return (
      <Empty title={active ? "The agent hasn't sent its plan yet" : "No checks ran"}>
        {active ? "Checks appear here once the agent picks up the scan." : "This scan finished without running any checks."}
      </Empty>
    );
  }
  return (
    <div className={classes.tableWrap}>
      <Table miw={880}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Check</Table.Th>
            <Table.Th>Status</Table.Th>
            <Table.Th>Findings</Table.Th>
            <Table.Th>Duration</Table.Th>
            <Table.Th>Elevation</Table.Th>
            <Table.Th>Data collected</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {sorted.map((r) => (
            <Table.Tr key={r.id}>
              <Table.Td>
                <div className={classes.runTitle}>{r.title}</div>
                <Text size="xs" c="dimmed">
                  <span className="sn-mono">{r.check_id}</span> v{r.check_version}, {humanize(r.category).toLowerCase()}
                </Text>
                {r.skip_reason ? <div className={classes.runReason}>{r.skip_reason}</div> : null}
                {r.error_message ? (
                  <div className={classes.runReason} data-kind="error">
                    {r.error_message}
                  </div>
                ) : null}
              </Table.Td>
              <Table.Td>
                <StatusBadge kind="check" value={r.status} />
              </Table.Td>
              <Table.Td className="sn-num">
                {r.finding_count > 0 ? (
                  <RowLink to={`/vulnerabilities?check_id=${encodeURIComponent(r.check_id)}&status=all`}>
                    {r.finding_count}
                  </RowLink>
                ) : r.status === "passed" || r.status === "failed" ? (
                  0
                ) : (
                  <span className="sn-dim">–</span>
                )}
              </Table.Td>
              <Table.Td className="sn-num">{formatDuration(r.duration_ms) || <span className="sn-dim">–</span>}</Table.Td>
              <Table.Td>
                {r.ran_elevated ? (
                  <Tag tone="warn">Ran as admin</Tag>
                ) : r.requires_elevation ? (
                  <Tooltip label="This check needs administrator rights. Queue an elevated scan to include it.">
                    <span tabIndex={0}>
                      <Tag>Needs admin</Tag>
                    </span>
                  </Tooltip>
                ) : (
                  <span className="sn-dim">Standard user</span>
                )}
              </Table.Td>
              <Table.Td>
                <div className={classes.dataCollected}>{r.data_collected || <span className="sn-dim">–</span>}</div>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </div>
  );
}

function ComparePanel({ scan }: { scan: ScanDetail }) {
  const earlier = useScans({ device_id: scan.device_id, limit: 100, offset: 0 });
  const options = useMemo(
    () =>
      (earlier.data?.items ?? [])
        .filter((s) => s.id !== scan.id && new Date(s.requested_at) <= new Date(scan.requested_at))
        .filter((s) => !ACTIVE_SCAN.has(s.status))
        .map((s) => ({
          value: String(s.id),
          label: `Scan ${s.id}: ${humanize(s.scan_type)}, ${humanize(s.status).toLowerCase()}, ${formatShort(s.requested_at)}`,
        })),
    [earlier.data, scan.id, scan.requested_at],
  );
  const [against, setAgainst] = useState<string | null>(null);
  const diff = useScanDiff(scan.id, against ? Number(against) : null);

  return (
    <Panel
      title="Compare with an earlier scan"
      description="New: seen in this scan only. Resolved: gone, and this scan actually ran the check that found it. A skipped check proves nothing, so its findings stay unchanged."
    >
      <Select
        label="Earlier scan of this device"
        placeholder={earlier.isPending ? "Loading scans" : options.length ? "Choose a scan" : "No earlier scans"}
        data={options}
        value={against}
        onChange={setAgainst}
        maw={460}
        mb="md"
        searchable
      />
      {diff.isFetching && !diff.data ? <Loading label="Comparing" /> : null}
      {diff.isError ? <ErrorState error={diff.error} /> : null}
      {diff.data ? (
        <div className={classes.diffCols}>
          <DiffColumn title="New" items={diff.data.new} empty="Nothing new." />
          <DiffColumn title="Resolved" items={diff.data.resolved} empty="Nothing resolved." />
          <DiffColumn title="Unchanged" items={diff.data.unchanged} empty="Nothing carried over." />
        </div>
      ) : null}
    </Panel>
  );
}

function DiffColumn({ title, items, empty }: { title: string; items: FindingOut[]; empty: string }) {
  return (
    <div className={classes.diffCol}>
      <h3>
        {title} <span className="sn-dim sn-num">({items.length})</span>
      </h3>
      {items.length === 0 ? (
        <Text size="sm" c="dimmed">
          {empty}
        </Text>
      ) : (
        <ul className={classes.diffList}>
          {items.map((f) => (
            <li key={f.id}>
              <SeverityBadge severity={f.severity} variant="inline" />
              <Anchor component={Link} to={`/vulnerabilities/${f.id}`} size="sm">
                {f.title}
              </Anchor>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
