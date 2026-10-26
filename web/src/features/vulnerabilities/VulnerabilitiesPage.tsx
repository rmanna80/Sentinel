import { Anchor, Group, Select, Switch, Table, Tabs, Text, TextInput, Tooltip } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { IconSearch } from "@tabler/icons-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import type { SoftwareQuery, VulnSummary } from "../../api/types";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { KevBadge, SeverityBadge } from "../../components/Severity";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "../devices/api";
import { useSoftware, useVulnSummary } from "./api";
import classes from "./Findings.module.css";
import { FindingsTab } from "./FindingsPage";

export function VulnerabilitiesPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "software" ? "software" : "findings";
  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description="Findings from device checks, and installed software matched against public vulnerability data."
      />
      <SummaryStrip />
      <Tabs
        value={tab}
        onChange={(v) => setParams(v === "software" ? { tab: "software" } : {}, { replace: true })}
        keepMounted={false}
        mt="md"
      >
        <Tabs.List mb="md">
          <Tabs.Tab value="findings">Findings</Tabs.Tab>
          <Tabs.Tab value="software">Software inventory</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="findings">
          <FindingsTab />
        </Tabs.Panel>
        <Tabs.Panel value="software">
          <SoftwareTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

function SummaryStrip() {
  const { deviceId } = useDeviceScope();
  const summary = useVulnSummary(deviceId);
  if (summary.isPending) return null;
  if (summary.isError) return <ErrorState error={summary.error} title="Vulnerability summary unavailable" />;
  return <SummaryBody s={summary.data} />;
}

function SummaryBody({ s }: { s: VulnSummary }) {
  const items = s.items;
  const scanned = items.matched + items.no_source + items.error + items.pending;
  return (
    <Panel
      title="Known vulnerabilities in installed software"
      description={
        s.last_matched_at ? (
          <>
            Last matched <Time value={s.last_matched_at} mode="relative" />. Intel sources and sync are on the{" "}
            <Anchor component={Link} to="/integrations" size="xs">
              Integrations
            </Anchor>{" "}
            page.
          </>
        ) : (
          "No inventory has been matched yet. Run a full or inventory scan."
        )
      }
    >
      <div className={classes.vulnFacts}>
        <div className={classes.vulnFact}>
          <div className={classes.vulnFactLabel}>Open vulnerabilities</div>
          <div className={classes.vulnFactValue}>{s.open_total}</div>
          <div className={classes.vulnFactNote}>
            {SEVERITIES.filter((k) => (s.by_severity[k] ?? 0) > 0)
              .map((k) => `${s.by_severity[k]} ${SEVERITY_LABEL[k].toLowerCase()}`)
              .join(", ") || "None open"}
          </div>
        </div>
        <div className={classes.vulnFact}>
          <div className={classes.vulnFactLabel}>Known exploited</div>
          <div className={classes.vulnFactValue}>{s.kev_count}</div>
          <div className={classes.vulnFactNote}>Listed in CISA KEV</div>
        </div>
        <div className={classes.vulnFact}>
          <div className={classes.vulnFactLabel}>Fix available</div>
          <div className={classes.vulnFactValue}>{s.with_fixed_version}</div>
          <div className={classes.vulnFactNote}>Have a fixed version listed</div>
        </div>
        <div className={classes.vulnFact}>
          <div className={classes.vulnFactLabel}>Software compared</div>
          <div className={classes.vulnFactValue}>
            {items.matched} <span className="sn-dim" style={{ fontSize: 13, fontWeight: 500 }}>of {scanned}</span>
          </div>
          <div className={classes.vulnFactNote}>
            {[
              items.no_source ? `${items.no_source} not compared` : "",
              items.pending ? `${items.pending} waiting` : "",
              items.error ? `${items.error} errors` : "",
            ]
              .filter(Boolean)
              .join(", ") || "All present items checked"}
          </div>
        </div>
      </div>
      {s.not_compared_reasons.length || s.nvd_undecidable || s.nvd_not_enriched ? (
        <ul className={classes.refs} style={{ marginTop: 10, color: "var(--sn-text-2)" }}>
          {s.not_compared_reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
          {s.nvd_undecidable ? (
            <li>{s.nvd_undecidable} NVD entries couldn't be compared by version, so they weren't reported.</li>
          ) : null}
          {s.nvd_not_enriched ? <li>{s.nvd_not_enriched} NVD entries are still awaiting NVD analysis.</li> : null}
        </ul>
      ) : null}
      {s.top_affected_software.length ? (
        <>
          <Text fw={650} size="sm" mt="md" mb={6}>
            Most affected software
          </Text>
          <div style={{ overflowX: "auto" }}>
            <Table miw={520}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Software</Table.Th>
                  <Table.Th>Ecosystem</Table.Th>
                  <Table.Th>Highest severity</Table.Th>
                  <Table.Th>Open</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {s.top_affected_software.map((a) => (
                  <Table.Tr key={`${a.ecosystem}:${a.name}`}>
                    <Table.Td>
                      <Group gap={8}>
                        <Link
                          className="sn-link"
                          to={`/vulnerabilities?source=vuln_matcher&q=${encodeURIComponent(a.name)}`}
                        >
                          {a.name}
                        </Link>
                        {a.kev ? <KevBadge /> : null}
                      </Group>
                    </Table.Td>
                    <Table.Td>{a.ecosystem}</Table.Td>
                    <Table.Td>
                      <SeverityBadge severity={a.highest_severity} variant="inline" />
                    </Table.Td>
                    <Table.Td className="sn-num">{a.open_findings}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
        </>
      ) : null}
    </Panel>
  );
}

const MATCH_LABEL: Record<string, { label: string; tone: "good" | "warn" | "danger" | "neutral"; help: string }> = {
  matched: { label: "Compared", tone: "good", help: "Checked against vulnerability data for its ecosystem." },
  no_source: { label: "No data source", tone: "neutral", help: "No enabled source covers this kind of software." },
  pending: { label: "Waiting", tone: "neutral", help: "Queued for matching on the next background run." },
  error: { label: "Error", tone: "danger", help: "The lookup failed; it is retried automatically." },
};

function SoftwareTab() {
  const { deviceId } = useDeviceScope();
  const devices = useDevices(true);
  const [search, setSearch] = useState("");
  const [q] = useDebouncedValue(search, 300);
  const [ecosystem, setEcosystem] = useState("");
  const [status, setStatus] = useState("");
  const [presentOnly, setPresentOnly] = useState(true);
  const [page, setPage] = useState({ limit: 100, offset: 0 });
  const query: SoftwareQuery = {
    device_id: deviceId ?? undefined,
    q: q.trim() || undefined,
    ecosystem: ecosystem || undefined,
    match_status: (status || undefined) as SoftwareQuery["match_status"],
    present_only: presentOnly,
    ...page,
  };
  const sw = useSoftware(query);
  const names = new Map((devices.data ?? []).map((d) => [d.id, d.name]));

  return (
    <Panel padded={false}>
      <div className={classes.filters} role="search" aria-label="Filter software">
        <TextInput
          size="xs"
          label="Search"
          placeholder="Name or publisher"
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => {
            setSearch(e.currentTarget.value);
            setPage((p) => ({ ...p, offset: 0 }));
          }}
          w={240}
        />
        <TextInput
          size="xs"
          label="Ecosystem"
          placeholder="Any"
          w={140}
          value={ecosystem}
          onChange={(e) => {
            setEcosystem(e.currentTarget.value.trim());
            setPage((p) => ({ ...p, offset: 0 }));
          }}
        />
        <Select
          size="xs"
          label="Matching"
          w={160}
          data={[{ value: "", label: "Any" }, ...Object.entries(MATCH_LABEL).map(([value, m]) => ({ value, label: m.label }))]}
          value={status}
          onChange={(v) => {
            setStatus(v ?? "");
            setPage((p) => ({ ...p, offset: 0 }));
          }}
        />
        <Switch
          size="sm"
          label="Installed now only"
          checked={presentOnly}
          onChange={(e) => setPresentOnly(e.currentTarget.checked)}
          className={classes.kevSwitch}
        />
      </div>
      {sw.isPending ? <Loading label="Loading software" /> : null}
      {sw.isError ? (
        <div style={{ padding: 16 }}>
          <ErrorState error={sw.error} onRetry={() => void sw.refetch()} />
        </div>
      ) : null}
      {sw.data && sw.data.items.length === 0 ? (
        <Empty title="No software recorded">
          The inventory fills in from full and inventory scans. Run one to see what's installed.
        </Empty>
      ) : null}
      {sw.data && sw.data.items.length > 0 ? (
        <>
          <div className={classes.tableWrap}>
            <Table miw={960} stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Software</Table.Th>
                  <Table.Th>Version</Table.Th>
                  <Table.Th>Device</Table.Th>
                  <Table.Th>Ecosystem</Table.Th>
                  <Table.Th>Matching</Table.Th>
                  <Table.Th>Open vulnerabilities</Table.Th>
                  <Table.Th>Last seen</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {sw.data.items.map((s) => {
                  const m = MATCH_LABEL[s.match_status] ?? { label: humanize(s.match_status), tone: "neutral" as const, help: "" };
                  return (
                    <Table.Tr key={s.id}>
                      <Table.Td>
                        <div style={{ fontWeight: 550 }}>{s.name}</div>
                        <Text size="xs" c="dimmed">
                          {[s.publisher, s.location].filter(Boolean).join(", ")}
                          {!s.is_present ? " (no longer installed)" : ""}
                        </Text>
                      </Table.Td>
                      <Table.Td className="sn-mono">{s.version ?? <span className="sn-dim">Unknown</span>}</Table.Td>
                      <Table.Td>{names.get(s.device_id) ?? `Device ${s.device_id}`}</Table.Td>
                      <Table.Td>{s.ecosystem}</Table.Td>
                      <Table.Td>
                        <Tooltip label={s.match_reason ?? m.help} disabled={!(s.match_reason ?? m.help)}>
                          <span tabIndex={0}>
                            <Tag tone={m.tone}>{m.label}</Tag>
                          </span>
                        </Tooltip>
                        {s.match_source ? (
                          <Text size="xs" c="dimmed" mt={3}>
                            via {s.match_source.toUpperCase()}
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td className="sn-num">
                        {s.open_vulnerabilities > 0 ? (
                          <Link
                            className="sn-link"
                            to={`/vulnerabilities?source=vuln_matcher&q=${encodeURIComponent(s.name)}`}
                          >
                            {s.open_vulnerabilities}
                          </Link>
                        ) : s.match_status === "matched" ? (
                          0
                        ) : (
                          <span className="sn-dim">–</span>
                        )}
                      </Table.Td>
                      <Table.Td>
                        <Time value={s.last_seen_at} mode="relative" />
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </div>
          <Pager total={sw.data.total} limit={page.limit} offset={page.offset} pageSizes={[50, 100, 200]} onChange={setPage} />
        </>
      ) : null}
    </Panel>
  );
}
