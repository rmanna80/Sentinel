import { Drawer, Group, MultiSelect, SegmentedControl, Stack, Table, Tabs, Text, TextInput } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { IconSearch } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { LogsQuery, LogStats } from "../../api/types";
import { ChartTooltipBody, LegendKey } from "../../components/ChartTooltip";
import { Facts } from "../../components/Facts";
import { JsonView } from "../../components/JsonView";
import { LogEventsTable } from "../../components/LogEventsTable";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { RowLink } from "../../components/RowLink";
import { SeverityBadge, SeverityGlyph } from "../../components/Severity";
import { StatusBadge } from "../../components/Status";
import { Time } from "../../components/Time";
import { useChartColors } from "../../lib/chartTheme";
import { formatDay, humanize } from "../../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "../devices/api";
import { useLogEvent, useLogSearch, useLogStats } from "./api";
import classes from "./Logs.module.css";

function toIso(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export function LogsPage() {
  const [params, setParams] = useSearchParams();
  const eventId = params.get("event") ? Number(params.get("event")) : null;
  const tab = params.get("tab") === "stats" ? "stats" : "search";
  const setTab = (v: string | null) => {
    const next = new URLSearchParams(params);
    if (v === "stats") next.set("tab", "stats");
    else next.delete("tab");
    setParams(next, { replace: true });
  };
  const closeEvent = () => {
    const next = new URLSearchParams(params);
    next.delete("event");
    setParams(next, { replace: true });
  };
  const openEvent = (id: number) => {
    const next = new URLSearchParams(params);
    next.set("event", String(id));
    setParams(next);
  };

  return (
    <>
      <PageHeader
        title="Logs and events"
        description="Security-relevant events collected by log scans, normalized across Windows and Linux. Messages are shown as plain text."
      />
      <Tabs value={tab} onChange={setTab} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="search">Event search</Tabs.Tab>
          <Tabs.Tab value="stats">Statistics</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="search">
          <SearchTab onOpen={openEvent} />
        </Tabs.Panel>
        <Tabs.Panel value="stats">
          <StatsTab />
        </Tabs.Panel>
      </Tabs>
      <Drawer opened={eventId !== null} onClose={closeEvent} position="right" size="lg" title="Log event">
        {eventId !== null ? <EventDetail id={eventId} /> : null}
      </Drawer>
    </>
  );
}

function SearchTab({ onOpen }: { onOpen: (id: number) => void }) {
  const { deviceId } = useDeviceScope();
  const devices = useDevices(true);
  const names = useMemo(() => new Map((devices.data ?? []).map((d) => [d.id, d.name])), [devices.data]);
  const [qInput, setQInput] = useState("");
  const [q] = useDebouncedValue(qInput.trim(), 300);
  const [severity, setSeverity] = useState<string[]>([]);
  const [category, setCategory] = useState("");
  const [action, setAction] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [page, setPage] = useState({ limit: 100, offset: 0 });
  const query: LogsQuery = {
    device_id: deviceId ?? undefined,
    severity: severity.length ? severity : undefined,
    category: category.trim() || undefined,
    action: action.trim() ? action.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
    since: toIso(since),
    until: toIso(until),
    q: q || undefined,
    ...page,
  };
  const logs = useLogSearch(query);
  const reset = () => setPage((p) => ({ ...p, offset: 0 }));

  return (
    <Panel padded={false}>
      <div className={classes.filters} role="search" aria-label="Filter log events">
        <TextInput size="xs" label="Keyword" placeholder="Message, user, IP or process" leftSection={<IconSearch size={14} />} value={qInput} onChange={(e) => { setQInput(e.currentTarget.value); reset(); }} w={240} />
        <MultiSelect
          size="xs"
          label="Severity"
          w={220}
          data={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))}
          value={severity}
          onChange={(v) => { setSeverity(v); reset(); }}
          placeholder={severity.length ? undefined : "Any"}
          clearable
        />
        <TextInput size="xs" label="Category" placeholder="e.g. authentication" w={150} value={category} onChange={(e) => { setCategory(e.currentTarget.value); reset(); }} />
        <TextInput size="xs" label="Action" placeholder="e.g. logon_failed" w={160} value={action} onChange={(e) => { setAction(e.currentTarget.value); reset(); }} />
        <TextInput size="xs" label="From" type="datetime-local" value={since} onChange={(e) => { setSince(e.currentTarget.value); reset(); }} />
        <TextInput size="xs" label="Until" type="datetime-local" value={until} onChange={(e) => { setUntil(e.currentTarget.value); reset(); }} />
      </div>
      {logs.isPending ? <Loading label="Searching events" /> : null}
      {logs.isError ? (
        <div style={{ padding: 16 }}>
          <ErrorState error={logs.error} onRetry={() => void logs.refetch()} />
        </div>
      ) : null}
      {logs.data && logs.data.items.length === 0 ? (
        <Empty title="No events match">
          Events arrive from full and logs scans. If you haven't run one, start a logs scan from Security scans.
        </Empty>
      ) : null}
      {logs.data && logs.data.items.length > 0 ? (
        <>
          <LogEventsTable events={logs.data.items} onOpen={onOpen} showDevice={deviceId === null} deviceNames={names} />
          <Pager total={logs.data.total} limit={page.limit} offset={page.offset} onChange={setPage} pageSizes={[50, 100, 250]} />
        </>
      ) : null}
    </Panel>
  );
}

function EventDetail({ id }: { id: number }) {
  const ev = useLogEvent(id);
  if (ev.isPending) return <Loading />;
  if (ev.isError) return <ErrorState error={ev.error} />;
  const e = ev.data;
  return (
    <Stack gap="md">
      <Group gap="sm">
        <SeverityBadge severity={e.severity} />
        <Text fw={650}>{humanize(e.action)}</Text>
      </Group>
      <div className={classes.message}>{e.message}</div>
      <Facts
        items={[
          ["When", <Time key="t" value={e.occurred_at} />],
          ["Device", e.device_name ? <Link key="d" to={`/devices/${e.device_id}`} className="sn-link">{e.device_name}</Link> : `Device ${e.device_id}`],
          ["Source", <span key="s" className="sn-mono">{e.source}{e.event_id ? ` (event ${e.event_id})` : ""}</span>],
          ["Category", humanize(e.category)],
          ["Outcome", e.outcome ? humanize(e.outcome) : "–"],
          ["User", e.user ? <span key="u" className="sn-mono">{e.user}</span> : "–"],
          ["Source IP", e.source_ip ? <span key="i" className="sn-mono">{e.source_ip}</span> : "–"],
          ["Process", e.process ? <span key="p" className="sn-mono">{e.process}</span> : "–"],
          ["Record", <span key="r" className="sn-mono">{e.record_id}</span>],
          ["Collected by", e.scan_id ? <Link key="sc" to={`/scans/${e.scan_id}`} className="sn-link">Scan {e.scan_id}</Link> : "–"],
          ["Ingested", <Time key="in" value={e.ingested_at} />],
        ]}
      />
      {e.alerts.length ? (
        <div>
          <Text fw={650} size="sm" mb={6}>
            Alerts that include this event
          </Text>
          <Table>
            <Table.Tbody>
              {e.alerts.map((a) => (
                <Table.Tr key={a.id}>
                  <Table.Td>
                    <SeverityBadge severity={a.severity} variant="inline" />
                  </Table.Td>
                  <Table.Td>
                    <RowLink to={`/threats/alerts/${a.id}`}>{a.title}</RowLink>
                  </Table.Td>
                  <Table.Td>
                    <StatusBadge kind="alert" value={a.status} />
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </div>
      ) : null}
      <div>
        <Text fw={650} size="sm" mb={6}>
          Event data
        </Text>
        <JsonView value={e.data} maxHeight={360} />
      </div>
    </Stack>
  );
}

const STAT_RANGES = [
  { value: "1", label: "Today" },
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
];

function StatsTab() {
  const { deviceId } = useDeviceScope();
  const [days, setDays] = useState(7);
  const stats = useLogStats(days, deviceId);
  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          Counts by UTC calendar day, today included.
        </Text>
        <SegmentedControl size="xs" aria-label="Range" data={STAT_RANGES} value={String(days)} onChange={(v) => setDays(Number(v))} />
      </Group>
      {stats.isPending ? <Loading /> : null}
      {stats.isError ? <ErrorState error={stats.error} /> : null}
      {stats.data ? <StatsBody s={stats.data} /> : null}
    </Stack>
  );
}

function StatsBody({ s }: { s: LogStats }) {
  const c = useChartColors();
  if (s.total_events === 0) {
    return (
      <Panel>
        <Empty title="No events in this range">Run a logs scan to collect events.</Empty>
      </Panel>
    );
  }
  return (
    <div className={classes.statsGrid}>
      <Panel title="Sign-ins by day" description={`${s.total_events.toLocaleString()} events in total over ${s.days} day${s.days === 1 ? "" : "s"}.`}>
        <Group gap="md" mb={6}>
          <LegendKey color={c.series[0]} label="Successful" />
          <LegendKey color={c.series[1]} label="Failed" />
        </Group>
        <div aria-hidden="true">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={s.logons_by_day} margin={{ top: 8, right: 8, bottom: 0, left: -18 }} barGap={2}>
              <CartesianGrid stroke={c.grid} vertical={false} />
              <XAxis dataKey="date" tickFormatter={(d: string) => formatDay(`${d}T12:00:00Z`)} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={{ stroke: c.axis }} minTickGap={16} />
              <YAxis allowDecimals={false} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip
                cursor={{ fill: c.accentWash }}
                content={({ active, payload }) => {
                  const row = active && payload?.[0] ? (payload[0].payload as LogStats["logons_by_day"][number]) : null;
                  if (!row) return null;
                  return (
                    <ChartTooltipBody
                      title={formatDay(`${row.date}T12:00:00Z`)}
                      rows={[
                        { key: "s", color: c.series[0], label: "Successful", value: row.success },
                        { key: "f", color: c.series[1], label: "Failed", value: row.failure },
                      ]}
                    />
                  );
                }}
              />
              <Bar dataKey="success" fill={c.series[0]} maxBarSize={18} radius={[3, 3, 0, 0]} isAnimationActive={false} />
              <Bar dataKey="failure" fill={c.series[1]} maxBarSize={18} radius={[3, 3, 0, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <table className="sr-only-table">
          <caption>Sign-ins by day</caption>
          <tbody>
            {s.logons_by_day.map((d) => (
              <tr key={d.date}>
                <th scope="row">{d.date}</th>
                <td>{d.success} successful</td>
                <td>{d.failure} failed</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      <Panel title="Events by severity per day">
        <div aria-hidden="true">
          <ResponsiveContainer width="100%" height={226}>
            <BarChart data={s.events_by_day} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
              <CartesianGrid stroke={c.grid} vertical={false} />
              <XAxis dataKey="date" tickFormatter={(d: string) => formatDay(`${d}T12:00:00Z`)} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={{ stroke: c.axis }} minTickGap={16} />
              <YAxis allowDecimals={false} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip
                cursor={{ fill: c.accentWash }}
                content={({ active, payload }) => {
                  const row = active && payload?.[0] ? (payload[0].payload as LogStats["events_by_day"][number]) : null;
                  if (!row) return null;
                  return (
                    <ChartTooltipBody
                      title={formatDay(`${row.date}T12:00:00Z`)}
                      rows={SEVERITIES.map((sev) => ({ key: sev, color: c.severity[sev], label: SEVERITY_LABEL[sev], value: row[sev] }))}
                    />
                  );
                }}
              />
              <Legend
                verticalAlign="top"
                height={24}
                content={() => (
                  <Group gap="sm" justify="flex-start" pl={20}>
                    {SEVERITIES.map((sev) => (
                      <span key={sev} style={{ display: "inline-flex", gap: 4, alignItems: "center", fontSize: 12, color: "var(--sn-text-2)" }}>
                        <SeverityGlyph severity={sev} /> {SEVERITY_LABEL[sev]}
                      </span>
                    ))}
                  </Group>
                )}
              />
              {[...SEVERITIES].reverse().map((sev) => (
                <Bar key={sev} dataKey={sev} stackId="sev" fill={c.severity[sev]} maxBarSize={22} stroke={c.surface} strokeWidth={1} isAnimationActive={false} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Panel>
      <Panel title="Most frequent actions" padded={false}>
        <Table mt={8}>
          <Table.Tbody>
            {s.top_actions.map((a) => (
              <Table.Tr key={a.action}>
                <Table.Td>{humanize(a.action)}</Table.Td>
                <Table.Td className="sn-num" ta="right">
                  {a.count.toLocaleString()}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Panel>
      <Panel title="Repeated patterns" description="The same action by the same account from the same address, many times." padded={false}>
        {s.repeated_patterns.length === 0 ? (
          <Text size="sm" c="dimmed" p="md">
            Nothing repeated often enough to list.
          </Text>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <Table mt={8} miw={480}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Action</Table.Th>
                  <Table.Th>User</Table.Th>
                  <Table.Th>Source IP</Table.Th>
                  <Table.Th ta="right">Count</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {s.repeated_patterns.map((p, i) => (
                  <Table.Tr key={i}>
                    <Table.Td>{humanize(p.action)}</Table.Td>
                    <Table.Td className="sn-mono">{p.user ?? "–"}</Table.Td>
                    <Table.Td className="sn-mono">{p.source_ip ?? "–"}</Table.Td>
                    <Table.Td className="sn-num" ta="right">
                      {p.count.toLocaleString()}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
        )}
      </Panel>
      <Panel title="Events by device" padded={false}>
        <Table mt={8}>
          <Table.Tbody>
            {s.events_by_device.map((d) => (
              <Table.Tr key={d.device_id}>
                <Table.Td>{d.device_name ?? `Device ${d.device_id}`}</Table.Td>
                <Table.Td className="sn-num" ta="right">
                  {d.count.toLocaleString()}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Panel>
      <Panel title="Alerts raised in this range">
        <Group gap="lg">
          {SEVERITIES.map((sev) => (
            <span key={sev} style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 13 }}>
              <SeverityGlyph severity={sev} /> {SEVERITY_LABEL[sev]} <strong className="sn-num">{s.alerts_by_severity[sev] ?? 0}</strong>
            </span>
          ))}
        </Group>
        <Text size="xs" mt="sm">
          <Link to="/threats" className="sn-link">
            Open threat detection
          </Link>
        </Text>
      </Panel>
    </div>
  );
}
