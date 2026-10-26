import { Anchor, Button, Group, Text, Tooltip } from "@mantine/core";
import { IconArrowUpRight, IconRadar } from "@tabler/icons-react";
import { useState } from "react";
import { Link } from "react-router";
import type { DeviceSummary, FindingOut, Overview, RecentEvent } from "../../api/types";
import { DemoBadge, DemoBanner, isFixture } from "../../components/DemoData";
import { Meter } from "../../components/Meter";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { KevBadge, SeverityBadge } from "../../components/Severity";
import { OnlineState, StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { formatRelative, humanize } from "../../lib/format";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "../devices/api";
import { useOverview } from "./api";
import classes from "./Overview.module.css";
import { ScoreCard } from "./ScoreCard";
import { ScoreHistoryChart } from "./ScoreHistoryChart";
import { SeverityChart } from "./SeverityChart";

export function OverviewPage() {
  const { deviceId } = useDeviceScope();
  const [days, setDays] = useState(30);
  const overview = useOverview(deviceId, days);
  const devices = useDevices();
  const scopeName =
    deviceId === null ? "All devices" : (devices.data?.find((d) => d.id === deviceId)?.name ?? `Device ${deviceId}`);

  return (
    <>
      <PageHeader
        title="Overview"
        docTitle="Overview"
        description={`Security posture for ${scopeName.toLowerCase() === "all devices" ? "all enrolled devices" : scopeName}.`}
        actions={
          <Button component={Link} to="/scans?new=1" leftSection={<IconRadar size={16} />}>
            New scan
          </Button>
        }
      />
      {overview.isPending ? <Loading label="Loading overview" /> : null}
      {overview.isError ? <ErrorState error={overview.error} onRetry={() => void overview.refetch()} /> : null}
      {overview.data ? <OverviewBody data={overview.data} days={days} onDaysChange={setDays} /> : null}
    </>
  );
}

function OverviewBody({ data, days, onDaysChange }: { data: Overview; days: number; onDaysChange: (d: number) => void }) {
  if (data.devices.length === 0) {
    return (
      <Panel>
        <Empty
          title="No devices enrolled yet"
          action={
            <Button component={Link} to="/devices?enroll=1">
              Enroll a device
            </Button>
          }
        >
          Sentinel scans the devices you enroll. Enroll this computer first: you'll get a one-time code and the exact command to run.
        </Empty>
      </Panel>
    );
  }

  return (
    <div className={classes.stack}>
      {data.data_mode_notice ? <DemoBanner>{data.data_mode_notice}</DemoBanner> : null}

      <div className={classes.topGrid}>
        <ScoreCard
          score={data.score}
          rawScore={data.raw_score}
          coverage={data.coverage}
          checksCompleted={data.checks_completed}
          checksApplicable={data.checks_applicable}
          threatLevel={data.threat_level}
          scoreBasis={data.score_basis}
        />
        <div className={classes.rightCol}>
          <Counters data={data} />
          <ScanTimeline data={data} />
        </div>
      </div>

      <div className={classes.chartGrid}>
        <Panel title="Open findings by severity" description="Includes accepted risk; resolved findings aren't counted.">
          <SeverityChart counts={data.severity_counts} />
        </Panel>
        <Panel title="Score history" description="One point per completed full or posture scan.">
          <ScoreHistoryChart history={data.score_history} devices={data.devices} days={days} onDaysChange={onDaysChange} />
        </Panel>
      </div>

      <div className={classes.listGrid}>
        <Panel
          title="Recommended actions"
          description="Open critical, high and medium findings, known-exploited first."
          actions={
            <Anchor component={Link} to="/vulnerabilities" size="xs" fw={600}>
              All findings
            </Anchor>
          }
          padded={false}
        >
          <Recommended items={data.recommended_actions} devices={data.devices} />
        </Panel>
        <Panel title="Recent security events" padded={false}>
          <RecentEvents items={data.recent_events} devices={data.devices} />
        </Panel>
      </div>

      <Panel
        title="Device health"
        description="Latest readings each device reported."
        actions={
          <Anchor component={Link} to="/diagnostics" size="xs" fw={600}>
            Diagnostics
          </Anchor>
        }
      >
        <DeviceTiles devices={data.devices} />
      </Panel>
    </div>
  );
}

function Counter({ label, value, to, hint }: { label: string; value: number; to?: string; hint?: string }) {
  const body = (
    <>
      <span className={classes.counterValue}>{value.toLocaleString()}</span>
      <span className={classes.counterLabel}>{label}</span>
    </>
  );
  const el = to ? (
    <Link to={to} className={classes.counter} aria-label={`${label}: ${value}`}>
      {body}
    </Link>
  ) : (
    <div className={classes.counter}>{body}</div>
  );
  return hint ? <Tooltip label={hint}>{el}</Tooltip> : el;
}

function Counters({ data }: { data: Overview }) {
  return (
    <div className={classes.counters}>
      <Counter label="Open findings" value={data.open_findings} to="/vulnerabilities" />
      <Counter
        label="Unresolved"
        value={data.unresolved_findings}
        to="/vulnerabilities"
        hint="Open findings not marked as accepted risk"
      />
      <Counter label="Vulnerabilities" value={data.vulnerabilities} to="/vulnerabilities?category=vulnerability" />
      <Counter label="Open alerts" value={data.open_alerts} to="/threats" />
      <Counter
        label={"Suspicious events, 24\u00a0h"}
        value={data.suspicious_events_24h}
        to="/logs"
        hint="Log events of low severity or higher in the last 24 hours"
      />
    </div>
  );
}

function ScanTimeline({ data }: { data: Overview }) {
  const last = data.last_scan;
  return (
    <div className={classes.scanStrip}>
      <div className={classes.scanCell}>
        <span className={classes.scanLabel}>Last scan</span>
        {last ? (
          <span className={classes.scanValue}>
            <Link to={`/scans/${last.id}`} className="sn-link">
              {humanize(last.scan_type)} scan
            </Link>{" "}
            <StatusBadge kind="scan" value={last.status} />
            {isFixture(last.data_mode) ? <DemoBadge /> : null}
            <span className={classes.scanTime}>
              <Time value={last.completed_at ?? last.requested_at} mode="relative" />
            </span>
          </span>
        ) : (
          <span className={classes.scanValue}>
            <span className="sn-dim">No scans yet</span>
          </span>
        )}
      </div>
      <div className={classes.scanCell}>
        <span className={classes.scanLabel}>Last successful</span>
        <span className={classes.scanValue}>
          <Time value={data.last_successful_scan_at} empty="None yet" />
        </span>
      </div>
      <div className={classes.scanCell}>
        <span className={classes.scanLabel}>Next scheduled</span>
        <span className={classes.scanValue}>
          {data.next_scheduled_at ? (
            <Time value={data.next_scheduled_at} />
          ) : (
            <span className="sn-dim">
              Nothing scheduled.{" "}
              <Link to="/schedules" className="sn-link">
                Schedule scans
              </Link>
            </span>
          )}
        </span>
      </div>
    </div>
  );
}

function deviceName(devices: DeviceSummary[], id: number | null | undefined): string {
  if (id === null || id === undefined) return "";
  return devices.find((d) => d.id === id)?.name ?? `Device ${id}`;
}

function Recommended({ items, devices }: { items: FindingOut[]; devices: DeviceSummary[] }) {
  if (items.length === 0) {
    return (
      <Empty title="Nothing urgent">
        No open critical, high or medium findings. Keep scanning on a schedule so new problems show up here.
      </Empty>
    );
  }
  return (
    <ol className={classes.rows}>
      {items.map((f) => (
        <li key={f.id}>
          <Link to={`/vulnerabilities/${f.id}`} className={classes.rowLink}>
            <span className={classes.rowSev}>
              <SeverityBadge severity={f.severity} />
            </span>
            <span className={classes.rowMain}>
              <span className={classes.rowTitle}>{f.title}</span>
              <span className={classes.rowMeta}>
                {deviceName(devices, f.device_id)}
                {f.cve_id ? <span className="sn-mono">{f.cve_id}</span> : null}
                <span>seen {formatRelative(f.last_seen_at)}</span>
              </span>
            </span>
            <span className={classes.rowEnd}>
              {f.kev ? <KevBadge /> : null}
              <IconArrowUpRight size={15} className={classes.rowArrow} aria-hidden="true" />
            </span>
          </Link>
        </li>
      ))}
    </ol>
  );
}

const EVENT_KIND: Record<string, string> = { alert: "Alert", log: "Log event", scan: "Scan" };

function RecentEvents({ items, devices }: { items: RecentEvent[]; devices: DeviceSummary[] }) {
  if (items.length === 0) {
    return <Empty title="No recent events">Completed scans, alerts and notable log events appear here.</Empty>;
  }
  return (
    <ul className={classes.rows}>
      {items.map((e, i) => (
        <li key={`${e.kind}-${e.link}-${i}`}>
          <Link to={e.link} className={classes.rowLink}>
            <span className={classes.rowSev}>
              <SeverityBadge severity={e.severity} variant="inline" />
            </span>
            <span className={classes.rowMain}>
              <span className={classes.rowTitle}>{e.title}</span>
              <span className={classes.rowMeta}>
                <Tag>{EVENT_KIND[e.kind] ?? humanize(e.kind)}</Tag>
                {deviceName(devices, e.device_id)}
                <span>{formatRelative(e.ts)}</span>
              </span>
            </span>
            <span className={classes.rowEnd}>
              <IconArrowUpRight size={15} className={classes.rowArrow} aria-hidden="true" />
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

function diskReadings(metrics: Record<string, number>): [string, number][] {
  return Object.entries(metrics)
    .filter(([k]) => k === "disk_percent" || k.startsWith("disk_percent:"))
    .map(([k, v]): [string, number] => [k === "disk_percent" ? "Disk" : `Disk ${k.slice("disk_percent:".length)}`, v])
    .sort((a, b) => b[1] - a[1]);
}

function DeviceTiles({ devices }: { devices: DeviceSummary[] }) {
  return (
    <div className={classes.tiles}>
      {devices.map((d) => {
        const disks = diskReadings(d.latest_metrics);
        const worstDisk = disks[0];
        const hasMetrics = Object.keys(d.latest_metrics).length > 0;
        return (
          <Link key={d.id} to={`/devices/${d.id}`} className={classes.tile}>
            <Group justify="space-between" gap={6} wrap="nowrap">
              <Text fw={650} size="sm" truncate>
                {d.name}
              </Text>
              <OnlineState online={d.online} />
            </Group>
            <Text size="xs" c="dimmed" truncate>
              {d.os_name} {d.edition ?? ""} {d.os_version}
            </Text>
            <div className={classes.tileMeters}>
              {hasMetrics ? (
                <>
                  <Meter label="CPU" value={d.latest_metrics.cpu_percent} />
                  <Meter label="Memory" value={d.latest_metrics.memory_percent} />
                  <Meter label={worstDisk ? worstDisk[0] : "Disk"} value={worstDisk ? worstDisk[1] : null} />
                </>
              ) : (
                <Text size="xs" c="dimmed">
                  No readings yet. The agent reports CPU, memory and disk while it runs.
                </Text>
              )}
            </div>
            <div className={classes.tileFoot}>
              <span>
                Score{" "}
                <strong className="sn-num">{d.score === null ? "Incomplete" : d.score}</strong>
              </span>
              <span>
                <strong className="sn-num">{d.open_findings}</strong> open
              </span>
            </div>
          </Link>
        );
      })}
    </div>
  );
}
