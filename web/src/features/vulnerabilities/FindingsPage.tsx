import { Chip, Group, MultiSelect, Select, Switch, Table, Text, TextInput } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { IconSearch } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import type { FindingsQuery } from "../../api/types";
import { Empty, ErrorState, Loading, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { RowLink } from "../../components/RowLink";
import { KevBadge, SeverityBadge } from "../../components/Severity";
import { StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "../devices/api";
import { useFindings } from "./api";
import { ExportFindingsButton } from "./ExportFindingsButton";
import classes from "./Findings.module.css";
import { FINDING_KIND, STATUS_LABEL } from "./workflow";

const STATUS_FILTERS = [
  { value: "open", label: "Open" },
  { value: "all", label: "All" },
  ...Object.entries(STATUS_LABEL).map(([value, label]) => ({ value, label })),
];

const SORTS = [
  { value: "severity", label: "Severity" },
  { value: "last_seen", label: "Last seen" },
  { value: "first_seen", label: "First seen" },
  { value: "cvss", label: "CVSS score" },
];

const SOURCES = [
  { value: "", label: "Any source" },
  { value: "agent", label: "Device checks" },
  { value: "vuln_matcher", label: "Vulnerability matching" },
];

export function FindingsTab() {
  const [params, setParams] = useSearchParams();
  const { deviceId } = useDeviceScope();
  const devices = useDevices(true);
  const [search, setSearch] = useState(params.get("q") ?? "");
  const [debounced] = useDebouncedValue(search, 300);

  const get = (k: string) => params.get(k);
  const status = get("status") ?? "open";
  const severity = params.getAll("severity");
  const limit = Number(get("limit") ?? 50);
  const offset = Number(get("offset") ?? 0);

  const update = (mut: (p: URLSearchParams) => void) => {
    const next = new URLSearchParams(params);
    mut(next);
    next.delete("offset");
    setParams(next, { replace: true });
  };
  const setOne = (k: string, v: string | null) =>
    update((p) => {
      if (v) p.set(k, v);
      else p.delete(k);
    });

  useEffect(() => {
    if ((params.get("q") ?? "") !== debounced) setOne("q", debounced.trim() || null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  const query: FindingsQuery = {
    device_id: deviceId ?? undefined,
    status,
    severity: severity.length ? severity : undefined,
    category: get("category") ?? undefined,
    kind: get("kind") ?? undefined,
    source: get("source") ?? undefined,
    check_id: get("check_id") ?? undefined,
    kev: get("kev") === "1" ? true : undefined,
    q: get("q") ?? undefined,
    sort: get("sort") ?? "severity",
    limit,
    offset,
  };
  const findings = useFindings(query);
  const names = useMemo(() => new Map((devices.data ?? []).map((d) => [d.id, d.name])), [devices.data]);
  const filtered =
    severity.length > 0 || !!get("category") || !!get("kind") || !!get("source") || !!get("kev") || !!get("q") || !!get("check_id");

  return (
    <>
      <Panel padded={false}>
        <div className={classes.filters} role="search" aria-label="Filter findings">
          <TextInput
            size="xs"
            label="Search"
            placeholder="Title, CVE, software or rule"
            leftSection={<IconSearch size={14} />}
            value={search}
            onChange={(e) => setSearch(e.currentTarget.value)}
            w={240}
          />
          <Select size="xs" label="Status" w={140} data={STATUS_FILTERS} value={status} onChange={(v) => setOne("status", v === "open" ? null : v)} />
          <MultiSelect
            size="xs"
            label="Severity"
            w={220}
            placeholder={severity.length ? undefined : "Any severity"}
            data={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))}
            value={severity}
            onChange={(v) =>
              update((p) => {
                p.delete("severity");
                v.forEach((s) => p.append("severity", s));
              })
            }
            clearable
          />
          <Select
            size="xs"
            label="Kind"
            w={140}
            data={[{ value: "", label: "Any kind" }, ...Object.entries(FINDING_KIND).map(([value, k]) => ({ value, label: k.label }))]}
            value={get("kind") ?? ""}
            onChange={(v) => setOne("kind", v || null)}
          />
          <Select size="xs" label="Source" w={180} data={SOURCES} value={get("source") ?? ""} onChange={(v) => setOne("source", v || null)} />
          <TextInput
            size="xs"
            label="Category"
            placeholder="Any"
            w={130}
            defaultValue={get("category") ?? ""}
            key={get("category") ?? "none"}
            onBlur={(e) => setOne("category", e.currentTarget.value.trim() || null)}
            onKeyDown={(e) => {
              if (e.key === "Enter") setOne("category", e.currentTarget.value.trim() || null);
            }}
          />
          <Select size="xs" label="Sort by" w={130} data={SORTS} value={get("sort") ?? "severity"} onChange={(v) => setOne("sort", v === "severity" ? null : v)} />
          <ExportFindingsButton query={query} />
          <Switch
            size="sm"
            label="Known exploited only"
            checked={get("kev") === "1"}
            onChange={(e) => setOne("kev", e.currentTarget.checked ? "1" : null)}
            className={classes.kevSwitch}
          />
        </div>
        {get("check_id") ? (
          <Group gap="xs" px="md" py={8} className={classes.activeFilter}>
            <Text size="xs" c="dimmed">
              Showing findings from check
            </Text>
            <Chip size="xs" checked onChange={() => setOne("check_id", null)} aria-label="Remove check filter">
              <span className="sn-mono">{get("check_id")}</span>
            </Chip>
          </Group>
        ) : null}

        {findings.isPending ? <Loading label="Loading findings" /> : null}
        {findings.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorState error={findings.error} onRetry={() => void findings.refetch()} />
          </div>
        ) : null}
        {findings.data && findings.data.items.length === 0 ? (
          <Empty title={filtered || status !== "open" ? "No findings match these filters" : "No open findings"}>
            {filtered || status !== "open"
              ? "Clear a filter to see more."
              : "Nothing is open right now. Findings appear here after scans, and close when a re-run of their check passes."}
          </Empty>
        ) : null}
        {findings.data && findings.data.items.length > 0 ? (
          <>
            <div className={classes.tableWrap}>
              <Table miw={980} stickyHeader>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th w={110}>Severity</Table.Th>
                    <Table.Th>Finding</Table.Th>
                    <Table.Th>Device</Table.Th>
                    <Table.Th>Kind</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>CVSS</Table.Th>
                    <Table.Th>Last seen</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {findings.data.items.map((f) => (
                    <Table.Tr key={f.id}>
                      <Table.Td>
                        <SeverityBadge severity={f.severity} />
                      </Table.Td>
                      <Table.Td>
                        <RowLink to={`/vulnerabilities/${f.id}`}>{f.title}</RowLink>
                        <div className={classes.sub}>
                          {f.kev ? <KevBadge /> : null}
                          {f.cve_id ? <span className="sn-mono">{f.cve_id}</span> : null}
                          {f.affected_software ? <span>{f.affected_software}</span> : null}
                          <span>{humanize(f.category)}</span>
                        </div>
                      </Table.Td>
                      <Table.Td>{names.get(f.device_id) ?? `Device ${f.device_id}`}</Table.Td>
                      <Table.Td>
                        <Tag title={FINDING_KIND[f.finding_kind]?.help}>{FINDING_KIND[f.finding_kind]?.label ?? humanize(f.finding_kind)}</Tag>
                        <Text size="xs" c="dimmed" mt={3}>
                          {humanize(f.confidence)} confidence
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <StatusBadge kind="finding" value={f.status} />
                      </Table.Td>
                      <Table.Td className="sn-num">
                        {f.cvss_score !== null ? f.cvss_score.toFixed(1) : <span className="sn-dim">–</span>}
                      </Table.Td>
                      <Table.Td>
                        <Time value={f.last_seen_at} mode="relative" />
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </div>
            <Pager
              total={findings.data.total}
              limit={limit}
              offset={offset}
              pageSizes={[25, 50, 100, 200]}
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
    </>
  );
}
