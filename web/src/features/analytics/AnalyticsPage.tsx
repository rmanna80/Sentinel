import { Button, Group, Modal, MultiSelect, SegmentedControl, Select, Stack, Table, Tabs, Text, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDownload, IconFileText, IconTrash } from "@tabler/icons-react";
import { useState, type ReactNode } from "react";
import { useSearchParams } from "react-router";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { downloadFile, errorMessage } from "../../api/client";
import type { Analytics, AnalyticsQuery, ReportCreate, ReportOut } from "../../api/types";
import { ChartTooltipBody, LegendKey } from "../../components/ChartTooltip";
import { DemoBadge } from "../../components/DemoData";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { SeverityGlyph } from "../../components/Severity";
import { Time } from "../../components/Time";
import { useChartColors } from "../../lib/chartTheme";
import { formatBytes, formatDay, formatPercent, humanize } from "../../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "../devices/api";
import { ScoreHistoryChart } from "../overview/ScoreHistoryChart";
import { SeverityChart } from "../overview/SeverityChart";
import { useAnalytics, useCreateReport, useDeleteReport, useReports } from "./api";
import classes from "./Analytics.module.css";

const RANGES = [
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
];

export function AnalyticsPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "reports" ? "reports" : "analytics";
  return (
    <>
      <PageHeader
        title="Analytics and reports"
        description="Trends computed from stored data. A metric with nothing collected behind it says so instead of showing a guess."
      />
      <Tabs value={tab} onChange={(v) => setParams(v === "reports" ? { tab: "reports" } : {}, { replace: true })} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="analytics">Analytics</Tabs.Tab>
          <Tabs.Tab value="reports">Reports</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="analytics">
          <AnalyticsTab />
        </Tabs.Panel>
        <Tabs.Panel value="reports">
          <ReportsTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

function AnalyticsTab() {
  const { deviceId } = useDeviceScope();
  const [days, setDays] = useState(30);
  const [severity, setSeverity] = useState<string[]>([]);
  const [category, setCategory] = useState("");
  const q: AnalyticsQuery = {
    days,
    device_id: deviceId ?? undefined,
    severity: severity.length ? severity : undefined,
    category: category.trim() || undefined,
  };
  const a = useAnalytics(q);
  return (
    <Stack gap="md">
      <Group gap="sm" align="flex-end" wrap="wrap">
        <SegmentedControl aria-label="Period" data={RANGES} value={String(days)} onChange={(v) => setDays(Number(v))} />
        <MultiSelect
          size="sm"
          w={240}
          aria-label="Severity"
          placeholder={severity.length ? undefined : "All severities"}
          data={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))}
          value={severity}
          onChange={setSeverity}
          clearable
        />
        <TextInput size="sm" w={180} aria-label="Category" placeholder="Any category" value={category} onChange={(e) => setCategory(e.currentTarget.value)} />
      </Group>
      {a.isPending ? <Loading label="Computing analytics" /> : null}
      {a.isError ? <ErrorState error={a.error} onRetry={() => void a.refetch()} /> : null}
      {a.data ? <AnalyticsBody a={a.data} days={days} /> : null}
    </Stack>
  );
}

function Unavailable({ reason }: { reason: string | undefined }) {
  return (
    <div className={classes.unavailable}>
      <Text size="sm" fw={600}>
        Unavailable
      </Text>
      <Text size="sm" c="dimmed">
        {reason ?? "Nothing was collected for this metric in this period."}
      </Text>
    </div>
  );
}

function Stat({ label, value, note }: { label: string; value: ReactNode; note?: ReactNode }) {
  return (
    <div className={classes.stat}>
      <div className={classes.statLabel}>{label}</div>
      <div className={classes.statValue}>{value}</div>
      {note ? <div className={classes.statNote}>{note}</div> : null}
    </div>
  );
}

function AnalyticsBody({ a, days }: { a: Analytics; days: number }) {
  const c = useChartColors();
  const devices = useDevices(true);
  const u = a.unavailable;
  return (
    <Stack gap="md">
      {a.filters.notes.length ? (
        <Text size="xs" c="dimmed">
          {a.filters.notes.join(" ")}
        </Text>
      ) : null}
      <div className={classes.stats}>
        <Stat
          label="Scan success rate"
          value={a.success_rate === null ? <span className="sn-dim">Unavailable</span> : formatPercent(a.success_rate)}
          note={a.success_rate === null ? u.success_rate : "Completed scans of all finished scans"}
        />
        <Stat
          label="Mean time to remediate"
          value={a.mean_time_to_remediate_days === null ? <span className="sn-dim">Unavailable</span> : `${a.mean_time_to_remediate_days.toFixed(1)} days`}
          note={
            a.mean_time_to_remediate_days === null
              ? u.mean_time_to_remediate_days
              : `Based on ${a.mean_time_to_remediate_count} verified resolution${a.mean_time_to_remediate_count === 1 ? "" : "s"}`
          }
        />
        <Stat label="Open remediation tasks" value={a.outstanding_tasks.open} note={`${a.outstanding_tasks.overdue} overdue`} />
      </div>

      <div className={classes.grid}>
        <Panel title="Score history">
          {a.score_history ? (
            <ScoreHistoryChart history={a.score_history} devices={devices.data ?? []} days={days} />
          ) : (
            <Unavailable reason={u.score_history} />
          )}
        </Panel>
        <Panel title="Open findings by severity">
          {a.vulns_by_severity ? <SeverityChart counts={a.vulns_by_severity} /> : <Unavailable reason={u.vulns_by_severity} />}
        </Panel>

        <Panel title="New and resolved findings by week">
          {a.new_vs_resolved_by_week ? (
            <>
              <Group gap="md" mb={6}>
                <LegendKey color={c.series[1]} label="New" />
                <LegendKey color={c.series[2]} label="Verified resolved" />
              </Group>
              <div aria-hidden="true">
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={a.new_vs_resolved_by_week} margin={{ top: 8, right: 8, bottom: 0, left: -18 }} barGap={2}>
                    <CartesianGrid stroke={c.grid} vertical={false} />
                    <XAxis dataKey="week_start" tickFormatter={(d: string) => formatDay(`${d}T12:00:00Z`)} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={{ stroke: c.axis }} minTickGap={12} />
                    <YAxis allowDecimals={false} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={false} />
                    <Tooltip
                      cursor={{ fill: c.accentWash }}
                      content={({ active, payload }) => {
                        const row = active && payload?.[0] ? (payload[0].payload as NonNullable<Analytics["new_vs_resolved_by_week"]>[number]) : null;
                        if (!row) return null;
                        return (
                          <ChartTooltipBody
                            title={`Week of ${formatDay(`${row.week_start}T12:00:00Z`)}`}
                            rows={[
                              { key: "n", color: c.series[1], label: "New", value: row.new },
                              { key: "r", color: c.series[2], label: "Verified resolved", value: row.resolved },
                            ]}
                          />
                        );
                      }}
                    />
                    <Bar dataKey="new" fill={c.series[1]} maxBarSize={16} radius={[3, 3, 0, 0]} isAnimationActive={false} />
                    <Bar dataKey="resolved" fill={c.series[2]} maxBarSize={16} radius={[3, 3, 0, 0]} isAnimationActive={false} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <table className="sr-only-table">
                <caption>New and resolved findings by week</caption>
                <tbody>
                  {a.new_vs_resolved_by_week.map((w) => (
                    <tr key={w.week_start}>
                      <th scope="row">{w.week_start}</th>
                      <td>{w.new} new</td>
                      <td>{w.resolved} resolved</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <Unavailable reason={u.new_vs_resolved_by_week} />
          )}
        </Panel>

        <Panel title="Alerts per day">
          {a.alerts_over_time ? (
            <>
              <Group gap="sm" mb={6}>
                {SEVERITIES.map((s) => (
                  <span key={s} className={classes.sevKey}>
                    <SeverityGlyph severity={s} /> {SEVERITY_LABEL[s]}
                  </span>
                ))}
              </Group>
              <div aria-hidden="true">
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={a.alerts_over_time} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                    <CartesianGrid stroke={c.grid} vertical={false} />
                    <XAxis dataKey="date" tickFormatter={(d: string) => formatDay(`${d}T12:00:00Z`)} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={{ stroke: c.axis }} minTickGap={16} />
                    <YAxis allowDecimals={false} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={false} />
                    <Tooltip
                      cursor={{ fill: c.accentWash }}
                      content={({ active, payload }) => {
                        const row = active && payload?.[0] ? (payload[0].payload as NonNullable<Analytics["alerts_over_time"]>[number]) : null;
                        if (!row) return null;
                        return (
                          <ChartTooltipBody
                            title={formatDay(`${row.date}T12:00:00Z`)}
                            rows={SEVERITIES.map((s) => ({ key: s, color: c.severity[s], label: SEVERITY_LABEL[s], value: row[s] }))}
                            footer={`${row.total} total`}
                          />
                        );
                      }}
                    />
                    {[...SEVERITIES].reverse().map((s) => (
                      <Bar key={s} dataKey={s} stackId="a" fill={c.severity[s]} maxBarSize={20} stroke={c.surface} strokeWidth={1} isAnimationActive={false} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </>
          ) : (
            <Unavailable reason={u.alerts_over_time} />
          )}
        </Panel>

        <Panel title="Device health (daily)">
          {a.health_history ? (
            <>
              <Group gap="md" mb={6}>
                <LegendKey color={c.series[0]} label="CPU average" />
                <LegendKey color={c.series[1]} label="Memory average" />
                <LegendKey color={c.series[2]} label="Fullest disk" />
              </Group>
              <div aria-hidden="true">
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={a.health_history} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                    <CartesianGrid stroke={c.grid} vertical={false} />
                    <XAxis dataKey="date" tickFormatter={(d: string) => formatDay(`${d}T12:00:00Z`)} tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={{ stroke: c.axis }} minTickGap={16} />
                    <YAxis domain={[0, 100]} unit="%" tick={{ fill: c.tick, fontSize: 11 }} tickLine={false} axisLine={false} />
                    <Tooltip
                      cursor={{ stroke: c.axis }}
                      content={({ active, payload }) => {
                        const row = active && payload?.[0] ? (payload[0].payload as NonNullable<Analytics["health_history"]>[number]) : null;
                        if (!row) return null;
                        const f = (v: number | null) => (v === null ? "No data" : `${v.toFixed(1)}%`);
                        return (
                          <ChartTooltipBody
                            title={formatDay(`${row.date}T12:00:00Z`)}
                            rows={[
                              { key: "c", color: c.series[0], label: "CPU average", value: f(row.cpu_avg) },
                              { key: "m", color: c.series[1], label: "Memory average", value: f(row.memory_avg) },
                              { key: "d", color: c.series[2], label: "Fullest disk", value: f(row.disk_max) },
                            ]}
                          />
                        );
                      }}
                    />
                    <Line dataKey="cpu_avg" stroke={c.series[0]} strokeWidth={2} dot={false} connectNulls={false} isAnimationActive={false} />
                    <Line dataKey="memory_avg" stroke={c.series[1]} strokeWidth={2} dot={false} connectNulls={false} isAnimationActive={false} />
                    <Line dataKey="disk_max" stroke={c.series[2]} strokeWidth={2} dot={false} connectNulls={false} isAnimationActive={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </>
          ) : (
            <Unavailable reason={u.health_history} />
          )}
        </Panel>

        <Panel title="Scan outcomes by week" padded={!a.scan_outcomes}>
          {a.scan_outcomes ? (
            <Table mt={8}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Week of</Table.Th>
                  <Table.Th ta="right">Completed</Table.Th>
                  <Table.Th ta="right">Partial</Table.Th>
                  <Table.Th ta="right">Failed</Table.Th>
                  <Table.Th ta="right">Cancelled</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {a.scan_outcomes.map((w) => (
                  <Table.Tr key={w.week_start}>
                    <Table.Td>{formatDay(`${w.week_start}T12:00:00Z`)}</Table.Td>
                    <Table.Td ta="right" className="sn-num">{w.completed}</Table.Td>
                    <Table.Td ta="right" className="sn-num">{w.partial}</Table.Td>
                    <Table.Td ta="right" className="sn-num">{w.failed}</Table.Td>
                    <Table.Td ta="right" className="sn-num">{w.cancelled}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          ) : (
            <Unavailable reason={u.scan_outcomes} />
          )}
        </Panel>

        <Panel title="Findings by device" padded={!a.findings_by_device}>
          {a.findings_by_device ? (
            <Table mt={8}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Device</Table.Th>
                  <Table.Th ta="right">Open</Table.Th>
                  {SEVERITIES.slice(0, 4).map((s) => (
                    <Table.Th key={s} ta="right">
                      {SEVERITY_LABEL[s]}
                    </Table.Th>
                  ))}
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {a.findings_by_device.map((d) => (
                  <Table.Tr key={d.device_id}>
                    <Table.Td>{d.name}</Table.Td>
                    <Table.Td ta="right" className="sn-num">{d.open}</Table.Td>
                    {SEVERITIES.slice(0, 4).map((s) => (
                      <Table.Td key={s} ta="right" className="sn-num">
                        {d.by_severity[s] ?? 0}
                      </Table.Td>
                    ))}
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          ) : (
            <Unavailable reason={u.findings_by_device} />
          )}
        </Panel>

        <Panel title="Open findings by category" padded={!a.vulns_by_category}>
          {a.vulns_by_category ? (
            Object.keys(a.vulns_by_category).length === 0 ? (
              <Text size="sm" c="dimmed" p="md">
                No open findings.
              </Text>
            ) : (
              <Table mt={8}>
                <Table.Tbody>
                  {Object.entries(a.vulns_by_category).map(([k, n]) => (
                    <Table.Tr key={k}>
                      <Table.Td>{humanize(k)}</Table.Td>
                      <Table.Td ta="right" className="sn-num">{n}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )
          ) : (
            <Unavailable reason={u.vulns_by_category} />
          )}
        </Panel>

        <Panel title="Most affected software" padded={!a.top_affected_software}>
          {a.top_affected_software ? (
            a.top_affected_software.length === 0 ? (
              <Text size="sm" c="dimmed" p="md">
                No software has open vulnerabilities.
              </Text>
            ) : (
              <Table mt={8}>
                <Table.Tbody>
                  {a.top_affected_software.map((s) => (
                    <Table.Tr key={s.name}>
                      <Table.Td>{s.name}</Table.Td>
                      <Table.Td ta="right" className="sn-num">{s.count}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )
          ) : (
            <Unavailable reason={u.top_affected_software} />
          )}
        </Panel>

        <Panel title="Repeated misconfigurations" description="Problems that were resolved and came back." padded={!a.repeated_misconfigurations}>
          {a.repeated_misconfigurations ? (
            a.repeated_misconfigurations.length === 0 ? (
              <Text size="sm" c="dimmed" p="md">
                Nothing has come back after being resolved.
              </Text>
            ) : (
              <Table mt={8}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Problem</Table.Th>
                    <Table.Th ta="right">Times reopened</Table.Th>
                    <Table.Th ta="right">Devices</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {a.repeated_misconfigurations.map((r) => (
                    <Table.Tr key={r.rule_id}>
                      <Table.Td>
                        {r.title}
                        <div className="sn-mono sn-dim" style={{ fontSize: 12 }}>
                          {r.rule_id}
                        </div>
                      </Table.Td>
                      <Table.Td ta="right" className="sn-num">{r.reopened_total}</Table.Td>
                      <Table.Td ta="right" className="sn-num">{r.devices}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )
          ) : (
            <Unavailable reason={u.repeated_misconfigurations} />
          )}
        </Panel>

        <Panel title="Email exposure checks" padded={!a.email_exposure_history}>
          {a.email_exposure_history ? (
            <Table mt={8}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>When</Table.Th>
                  <Table.Th>Address</Table.Th>
                  <Table.Th>Result</Table.Th>
                  <Table.Th ta="right">Breaches</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {a.email_exposure_history.map((e, i) => (
                  <Table.Tr key={i}>
                    <Table.Td>
                      <Time value={e.checked_at} mode="relative" />
                    </Table.Td>
                    <Table.Td>Address {e.identity_id}</Table.Td>
                    <Table.Td>{humanize(e.status)}</Table.Td>
                    <Table.Td ta="right" className="sn-num">
                      {e.breach_count ?? "–"}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          ) : (
            <Unavailable reason={u.email_exposure_history} />
          )}
        </Panel>
      </div>
    </Stack>
  );
}

// ------------------------------------------------------------------------------------------ reports

function ReportsTab() {
  const reports = useReports();
  const del = useDeleteReport();
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<ReportOut | null>(null);
  const download = (r: ReportOut) =>
    void downloadFile(`/api/reports/${r.id}/download`, undefined, `${r.title}.${r.kind}`).catch((err: unknown) =>
      notifications.show({ color: "red", title: "Download failed", message: errorMessage(err) }),
    );
  return (
    <Panel
      title="Reports"
      description="Built on this computer from stored data and saved in Sentinel's reports folder. The SHA-256 lets you check a copy wasn't changed."
      padded={false}
      actions={
        <Button size="xs" leftSection={<IconFileText size={14} />} onClick={() => setCreating(true)}>
          Create report
        </Button>
      }
    >
      {reports.isPending ? <Loading /> : null}
      {reports.isError ? <ErrorState error={reports.error} /> : null}
      {reports.data && reports.data.length === 0 ? (
        <Empty title="No reports yet" action={<Button onClick={() => setCreating(true)}>Create report</Button>}>
          A PDF summary is good for sharing; CSV and JSON are for spreadsheets and other tools.
        </Empty>
      ) : null}
      {reports.data && reports.data.length > 0 ? (
        <div style={{ overflowX: "auto" }}>
          <Table miw={880} mt={8}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Report</Table.Th>
                <Table.Th>Format</Table.Th>
                <Table.Th>Covers</Table.Th>
                <Table.Th>Created</Table.Th>
                <Table.Th>Size</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {reports.data.map((r) => {
                const scope = r.scope;
                const fixture = scope.fixture_data === true;
                return (
                  <Table.Tr key={r.id}>
                    <Table.Td>
                      <div style={{ fontWeight: 600 }}>{r.title}</div>
                      <Text size="xs" c="dimmed" className="sn-mono" style={{ overflowWrap: "anywhere" }}>
                        sha256 {r.sha256}
                      </Text>
                    </Table.Td>
                    <Table.Td>{r.kind.toUpperCase()}</Table.Td>
                    <Table.Td>
                      {typeof scope.days === "number" ? `${scope.days} days` : ""}
                      {typeof scope.device_id === "number" ? `, device ${scope.device_id}` : ", all devices"}
                      {fixture ? (
                        <div style={{ marginTop: 4 }}>
                          <DemoBadge />
                        </div>
                      ) : null}
                    </Table.Td>
                    <Table.Td>
                      <Time value={r.created_at} />
                    </Table.Td>
                    <Table.Td className="sn-num">{formatBytes(r.size_bytes)}</Table.Td>
                    <Table.Td>
                      <Group gap={4} justify="flex-end" wrap="nowrap">
                        <Button size="compact-sm" variant="default" leftSection={<IconDownload size={14} />} onClick={() => download(r)}>
                          Download
                        </Button>
                        <Button size="compact-sm" variant="subtle" color="red" aria-label={`Delete ${r.title}`} onClick={() => setRemoving(r)}>
                          <IconTrash size={15} />
                        </Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </div>
      ) : null}
      <CreateReportDialog opened={creating} onClose={() => setCreating(false)} />
      <Modal opened={removing !== null} onClose={() => setRemoving(null)} title="Delete this report?" size="sm">
        <Text size="sm">{removing?.title} and its file are deleted. You can create it again from current data.</Text>
        {del.isError ? (
          <Text c="red" size="sm" mt="sm" role="alert">
            {errorMessage(del.error)}
          </Text>
        ) : null}
        <Group justify="flex-end" mt="md">
          <Button variant="default" onClick={() => setRemoving(null)}>
            Keep it
          </Button>
          <Button color="red" loading={del.isPending} onClick={() => removing && del.mutate(removing.id, { onSuccess: () => setRemoving(null) })}>
            Delete report
          </Button>
        </Group>
      </Modal>
    </Panel>
  );
}

function CreateReportDialog({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { deviceId } = useDeviceScope();
  const devices = useDevices(true);
  const create = useCreateReport();
  const [form, setForm] = useState<ReportCreate>({ kind: "pdf", title: "Security posture report", device_id: deviceId, days: 30 });
  return (
    <Modal opened={opened} onClose={onClose} title="Create a report" size="md">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate(form, {
            onSuccess: (r) => {
              notifications.show({ message: `${r.title} created` });
              onClose();
            },
          });
        }}
      >
        <Stack gap="sm">
          <TextInput label="Title" value={form.title} onChange={(e) => setForm((f) => ({ ...f, title: e.currentTarget.value }))} maxLength={120} required data-autofocus />
          <Select
            label="Format"
            data={[
              { value: "pdf", label: "PDF summary" },
              { value: "csv", label: "CSV (findings and scans)" },
              { value: "json", label: "JSON (everything, machine-readable)" },
            ]}
            value={form.kind}
            onChange={(v) => v && setForm((f) => ({ ...f, kind: v as ReportCreate["kind"] }))}
          />
          <Select
            label="Devices"
            data={[{ value: "", label: "All devices" }, ...(devices.data ?? []).map((d) => ({ value: String(d.id), label: d.name }))]}
            value={form.device_id ? String(form.device_id) : ""}
            onChange={(v) => setForm((f) => ({ ...f, device_id: v ? Number(v) : null }))}
          />
          <Select
            label="Period"
            data={RANGES}
            value={String(form.days)}
            onChange={(v) => setForm((f) => ({ ...f, days: Number(v ?? 30) }))}
          />
          <Text size="xs" c="dimmed">
            If any included scan used demo (fixture) data, the report says so.
          </Text>
          {create.isError ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(create.error)}
            </Text>
          ) : null}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending} disabled={!form.title.trim()}>
              Create report
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
