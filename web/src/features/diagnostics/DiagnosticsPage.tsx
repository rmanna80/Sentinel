import { Anchor, Group, SegmentedControl, Select, Text } from "@mantine/core";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MetricSeries } from "../../api/types";
import { ChartTooltipBody, LegendKey } from "../../components/ChartTooltip";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { OnlineState } from "../../components/Status";
import { MAX_SERIES, useChartColors } from "../../lib/chartTheme";
import { formatDateTime, formatDay, formatTime } from "../../lib/format";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDeviceMetrics, useDevices } from "./api";
import classes from "./Diagnostics.module.css";

const RANGES = [
  { value: "6", label: "6 h" },
  { value: "24", label: "24 h" },
  { value: "168", label: "7 days" },
  { value: "720", label: "30 days" },
  { value: "2160", label: "90 days" },
];

interface Row {
  t: number;
  [series: string]: number;
}

function merge(series: MetricSeries[]): Row[] {
  const byTs = new Map<number, Row>();
  for (const s of series) {
    for (const p of s.points) {
      const t = new Date(p.ts).getTime();
      const row = byTs.get(t) ?? { t };
      row[s.metric] = p.value;
      byTs.set(t, row);
    }
  }
  return [...byTs.values()].sort((a, b) => a.t - b.t);
}

function diskLabel(metric: string): string {
  return metric === "disk_percent" ? "Disk" : metric.slice("disk_percent:".length);
}

export function DiagnosticsPage() {
  const { deviceId: scoped } = useDeviceScope();
  const devices = useDevices();
  const active = devices.data ?? [];
  const [picked, setPicked] = useState<number | null>(null);
  const deviceId = scoped ?? picked ?? active[0]?.id ?? null;
  const device = active.find((d) => d.id === deviceId);
  const [hours, setHours] = useState(24);
  const metrics = useDeviceMetrics(deviceId, hours);

  const groups = useMemo(() => {
    const all = metrics.data ?? [];
    const disks = all.filter((s) => s.metric === "disk_percent" || s.metric.startsWith("disk_percent:"));
    disks.sort((a, b) => (b.points.at(-1)?.value ?? 0) - (a.points.at(-1)?.value ?? 0));
    return {
      cpu: all.filter((s) => s.metric === "cpu_percent"),
      memory: all.filter((s) => s.metric === "memory_percent"),
      disks,
      other: all.filter((s) => !["cpu_percent", "memory_percent"].includes(s.metric) && !disks.includes(s)),
    };
  }, [metrics.data]);

  return (
    <>
      <PageHeader
        title="System diagnostics"
        description="CPU, memory and disk use the agent reported over time. Readings arrive about once a minute while the agent runs."
        actions={
          <Group gap="sm">
            {scoped === null ? (
              <Select
                aria-label="Device"
                size="sm"
                w={220}
                data={active.map((d) => ({ value: String(d.id), label: d.name }))}
                value={deviceId ? String(deviceId) : null}
                onChange={(v) => setPicked(v ? Number(v) : null)}
                placeholder="Choose a device"
              />
            ) : null}
            <SegmentedControl size="sm" aria-label="Time range" data={RANGES} value={String(hours)} onChange={(v) => setHours(Number(v))} />
          </Group>
        }
      />
      {devices.isPending ? <Loading /> : null}
      {devices.data && devices.data.length === 0 ? (
        <Panel>
          <Empty title="No devices enrolled">Enroll a device to see its health here.</Empty>
        </Panel>
      ) : null}
      {device ? (
        <Group gap="md" mb="md">
          <Text fw={650}>{device.name}</Text>
          <OnlineState online={device.online} />
          <Anchor component={Link} to={`/vulnerabilities?check_id=diag.resources&status=all`} size="sm">
            Resource findings (low disk, long uptime)
          </Anchor>
        </Group>
      ) : null}
      {metrics.isPending && deviceId !== null ? <Loading label="Loading readings" /> : null}
      {metrics.isError ? <ErrorState error={metrics.error} onRetry={() => void metrics.refetch()} /> : null}
      {metrics.data && metrics.data.length === 0 ? (
        <Panel>
          <Empty title="No readings in this range">
            The agent sends readings while it runs (not during demo-fixture runs). Start the agent or pick a longer range.
          </Empty>
        </Panel>
      ) : null}
      {metrics.data && metrics.data.length > 0 ? (
        <div className={classes.grid}>
          <MetricChart title="CPU" series={groups.cpu} hours={hours} />
          <MetricChart title="Memory" series={groups.memory} hours={hours} />
          <MetricChart title="Disk use" series={groups.disks} hours={hours} labeler={diskLabel} />
          {groups.other.map((s) => (
            <MetricChart key={s.metric} title={s.metric} series={[s]} hours={hours} />
          ))}
        </div>
      ) : null}
    </>
  );
}

function MetricChart({
  title,
  series,
  hours,
  labeler = () => title,
}: {
  title: string;
  series: MetricSeries[];
  hours: number;
  labeler?: (metric: string) => string;
}) {
  const c = useChartColors();
  const shown = series.slice(0, MAX_SERIES);
  const data = useMemo(() => merge(shown), [shown]);
  const latest = shown.map((s) => ({ metric: s.metric, value: s.points.at(-1)?.value }));
  const multi = shown.length > 1;
  const tick = (t: number) => {
    const iso = new Date(t).toISOString();
    return hours <= 24 ? formatTime(iso) : formatDay(iso);
  };

  return (
    <Panel
      title={title}
      description={
        latest.length === 1 && latest[0].value !== undefined ? `Latest ${latest[0].value.toFixed(0)}%` : undefined
      }
    >
      {shown.length === 0 ? (
        <Text size="sm" c="dimmed">
          No {title.toLowerCase()} readings in this range.
        </Text>
      ) : (
        <>
          {multi ? (
            <Group gap="md" mb={6}>
              {shown.map((s, i) => (
                <LegendKey
                  key={s.metric}
                  color={c.series[i]}
                  label={`${labeler(s.metric)} ${latest[i].value !== undefined ? `${latest[i].value?.toFixed(0)}%` : ""}`}
                />
              ))}
            </Group>
          ) : null}
          <div aria-hidden="true">
            <ResponsiveContainer width="100%" height={190}>
              <LineChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -18 }}>
                <CartesianGrid stroke={c.grid} vertical={false} />
                <XAxis
                  dataKey="t"
                  type="number"
                  scale="time"
                  domain={["dataMin", "dataMax"]}
                  tickFormatter={tick}
                  tick={{ fill: c.tick, fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: c.axis }}
                  minTickGap={36}
                />
                <YAxis domain={[0, 100]} ticks={[0, 50, 80, 100]} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={false} unit="%" />
                <ReferenceLine y={90} stroke={c.severity.high} strokeDasharray="3 3" ifOverflow="extendDomain" />
                <Tooltip
                  cursor={{ stroke: c.axis }}
                  content={({ active, payload }) => {
                    const row = active && payload?.[0] ? (payload[0].payload as Row) : null;
                    if (!row) return null;
                    return (
                      <ChartTooltipBody
                        title={formatDateTime(new Date(row.t).toISOString())}
                        rows={shown.map((s, i) => ({
                          key: s.metric,
                          color: c.series[i],
                          label: labeler(s.metric),
                          value: typeof row[s.metric] === "number" ? `${row[s.metric].toFixed(1)}%` : "No reading",
                        }))}
                      />
                    );
                  }}
                />
                {shown.map((s, i) => (
                  <Line
                    key={s.metric}
                    type="linear"
                    dataKey={s.metric}
                    stroke={c.series[i]}
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4, stroke: c.surface, strokeWidth: 2 }}
                    connectNulls={false}
                    isAnimationActive={false}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
          {series.length > MAX_SERIES ? (
            <Text size="xs" c="dimmed" mt={4}>
              Showing the {MAX_SERIES} fullest of {series.length} disks.
            </Text>
          ) : null}
          <Text size="xs" c="dimmed" mt={4}>
            Dashed line: 90%.
          </Text>
          <table className="sr-only-table">
            <caption>{title}, latest readings</caption>
            <tbody>
              {latest.map((l) => (
                <tr key={l.metric}>
                  <th scope="row">{labeler(l.metric)}</th>
                  <td>{l.value !== undefined ? `${l.value.toFixed(1)}%` : "No reading"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Panel>
  );
}
