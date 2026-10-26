import {
  Alert,
  Button,
  Group,
  Modal,
  MultiSelect,
  Select,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  Textarea,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconTrash, IconUpload } from "@tabler/icons-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { AlertsQuery, RuleOut } from "../../api/types";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { RowLink } from "../../components/RowLink";
import { SeverityBadge } from "../../components/Severity";
import { StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { useDeviceScope } from "../../layout/DeviceScope";
import {
  ALERT_STATUSES,
  INCIDENT_STATUSES,
  parseIocText,
  useAlerts,
  useDeleteIoc,
  useImportIocs,
  useIncidents,
  useIocs,
  useRules,
  useToggleRule,
} from "./api";
import classes from "./Threats.module.css";

const TABS = ["alerts", "incidents", "rules", "iocs"] as const;

export function ThreatsPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab = (TABS as readonly string[]).includes(raw ?? "") ? (raw as string) : "alerts";
  return (
    <>
      <PageHeader
        title="Threat detection"
        description="Alerts raised by detection rules over collected logs, grouped into incidents when they share an account or address. Rules only read logs; nothing is ever run on a device."
      />
      <Tabs value={tab} onChange={(v) => setParams(v && v !== "alerts" ? { tab: v } : {}, { replace: true })} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="alerts">Alerts</Tabs.Tab>
          <Tabs.Tab value="incidents">Incidents</Tabs.Tab>
          <Tabs.Tab value="rules">Detection rules</Tabs.Tab>
          <Tabs.Tab value="iocs">Indicator hashes</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="alerts">
          <AlertsTab />
        </Tabs.Panel>
        <Tabs.Panel value="incidents">
          <IncidentsTab />
        </Tabs.Panel>
        <Tabs.Panel value="rules">
          <RulesTab />
        </Tabs.Panel>
        <Tabs.Panel value="iocs">
          <IocsTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

function AlertsTab() {
  const { deviceId } = useDeviceScope();
  const [status, setStatus] = useState<string[]>(["open"]);
  const [severity, setSeverity] = useState<string[]>([]);
  const [page, setPage] = useState({ limit: 50, offset: 0 });
  const query: AlertsQuery = {
    status: status.length ? status : undefined,
    severity: severity.length ? severity : undefined,
    device_id: deviceId ?? undefined,
    ...page,
  };
  const alerts = useAlerts(query);
  return (
    <Panel padded={false}>
      <div className={classes.filters} role="search" aria-label="Filter alerts">
        <MultiSelect
          size="xs"
          label="Status"
          w={300}
          data={[{ value: "open", label: "Open (new, acknowledged, investigating)" }, ...ALERT_STATUSES.map((s) => ({ value: s, label: humanize(s) }))]}
          value={status}
          onChange={(v) => {
            setStatus(v);
            setPage((p) => ({ ...p, offset: 0 }));
          }}
          placeholder={status.length ? undefined : "Any status"}
          clearable
        />
        <MultiSelect
          size="xs"
          label="Severity"
          w={240}
          data={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))}
          value={severity}
          onChange={(v) => {
            setSeverity(v);
            setPage((p) => ({ ...p, offset: 0 }));
          }}
          placeholder={severity.length ? undefined : "Any severity"}
          clearable
        />
      </div>
      {alerts.isPending ? <Loading label="Loading alerts" /> : null}
      {alerts.isError ? (
        <div style={{ padding: 16 }}>
          <ErrorState error={alerts.error} onRetry={() => void alerts.refetch()} />
        </div>
      ) : null}
      {alerts.data && alerts.data.items.length === 0 ? (
        <Empty title={status.includes("open") && status.length === 1 && !severity.length ? "No open alerts" : "No alerts match"}>
          Alerts come from log scans. Run a full or logs scan, or schedule one daily, so detection rules have events to read.
        </Empty>
      ) : null}
      {alerts.data && alerts.data.items.length > 0 ? (
        <>
          <div className={classes.tableWrap}>
            <Table miw={980}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={110}>Severity</Table.Th>
                  <Table.Th>Alert</Table.Th>
                  <Table.Th>Device</Table.Th>
                  <Table.Th>Kind</Table.Th>
                  <Table.Th>Events</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Detected</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {alerts.data.items.map((a) => (
                  <Table.Tr key={a.id}>
                    <Table.Td>
                      <SeverityBadge severity={a.severity} />
                    </Table.Td>
                    <Table.Td>
                      <RowLink to={`/threats/alerts/${a.id}`}>{a.title}</RowLink>
                      <div className={classes.sub}>
                        {a.entity ? <span className="sn-mono">{a.entity}</span> : null}
                        <span className="sn-mono">{a.rule_id}</span>
                        {a.incident_id ? (
                          <RowLink to={`/threats/incidents/${a.incident_id}`}>Incident {a.incident_id}</RowLink>
                        ) : null}
                      </div>
                    </Table.Td>
                    <Table.Td>{a.device_name ?? `Device ${a.device_id}`}</Table.Td>
                    <Table.Td>
                      <KindTag kind={a.kind} confidence={a.confidence} />
                    </Table.Td>
                    <Table.Td className="sn-num">{a.event_count}</Table.Td>
                    <Table.Td>
                      <StatusBadge kind="alert" value={a.status} />
                    </Table.Td>
                    <Table.Td>
                      <Time value={a.detected_at} mode="relative" />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
          <Pager total={alerts.data.total} limit={page.limit} offset={page.offset} onChange={setPage} />
        </>
      ) : null}
    </Panel>
  );
}

export function KindTag({ kind, confidence }: { kind: string; confidence: string }) {
  const verified = kind === "verified";
  return (
    <Tooltip
      label={
        verified
          ? "Verified: directly observed in the logs."
          : "Heuristic: suspicious, not proof of an attack. Investigate before acting."
      }
    >
      <span tabIndex={0}>
        <Tag tone={verified ? "danger" : "warn"}>{verified ? "Verified" : "Heuristic"}</Tag>
        <Text size="xs" c="dimmed" mt={3} span display="block">
          {humanize(confidence)} confidence
        </Text>
      </span>
    </Tooltip>
  );
}

function IncidentsTab() {
  const { deviceId } = useDeviceScope();
  const [status, setStatus] = useState<string>("open");
  const [page, setPage] = useState({ limit: 50, offset: 0 });
  const incidents = useIncidents({ status: status ? [status] : undefined, device_id: deviceId ?? undefined, ...page });
  return (
    <Panel padded={false}>
      <div className={classes.filters}>
        <Select
          size="xs"
          label="Status"
          w={200}
          data={[{ value: "open", label: "Open or investigating" }, { value: "", label: "Any" }, ...INCIDENT_STATUSES.map((s) => ({ value: s, label: humanize(s) }))]}
          value={status}
          onChange={(v) => {
            setStatus(v ?? "");
            setPage((p) => ({ ...p, offset: 0 }));
          }}
        />
      </div>
      {incidents.isPending ? <Loading /> : null}
      {incidents.isError ? <ErrorState error={incidents.error} /> : null}
      {incidents.data && incidents.data.items.length === 0 ? (
        <Empty title="No incidents">
          An incident opens when alerts on one device share an account or address within two hours of each other.
        </Empty>
      ) : null}
      {incidents.data && incidents.data.items.length > 0 ? (
        <>
          <div className={classes.tableWrap}>
            <Table miw={860}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={110}>Severity</Table.Th>
                  <Table.Th>Incident</Table.Th>
                  <Table.Th>Device</Table.Th>
                  <Table.Th>Alerts</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Updated</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {incidents.data.items.map((i) => (
                  <Table.Tr key={i.id}>
                    <Table.Td>
                      <SeverityBadge severity={i.severity} />
                    </Table.Td>
                    <Table.Td>
                      <RowLink to={`/threats/incidents/${i.id}`}>{i.title}</RowLink>
                      <div className={classes.sub}>
                        {i.entities.slice(0, 4).map((e) => (
                          <span key={e} className="sn-mono">
                            {e}
                          </span>
                        ))}
                        {i.entities.length > 4 ? <span>+{i.entities.length - 4} more</span> : null}
                      </div>
                    </Table.Td>
                    <Table.Td>{i.device_name ?? `Device ${i.device_id}`}</Table.Td>
                    <Table.Td className="sn-num">{i.alert_count}</Table.Td>
                    <Table.Td>
                      <StatusBadge kind="incident" value={i.status} />
                    </Table.Td>
                    <Table.Td>
                      <Time value={i.updated_at} mode="relative" />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
          <Pager total={incidents.data.total} limit={page.limit} offset={page.offset} onChange={setPage} />
        </>
      ) : null}
    </Panel>
  );
}

function RulesTab() {
  const rules = useRules();
  const toggle = useToggleRule();
  const [open, setOpen] = useState<RuleOut | null>(null);
  if (rules.isPending) return <Loading />;
  if (rules.isError) return <ErrorState error={rules.error} onRetry={() => void rules.refetch()} />;
  return (
    <Panel
      padded={false}
      title="Detection rules"
      description="Every rule is defined in Sentinel's code and shown here in full. Turning a rule off stops new alerts from it; existing alerts stay."
    >
      {toggle.isError ? (
        <Alert color="red" variant="light" m="md" role="alert">
          {errorMessage(toggle.error)}
        </Alert>
      ) : null}
      <div className={classes.tableWrap}>
        <Table miw={900} mt={8}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={110}>Severity</Table.Th>
              <Table.Th>Rule</Table.Th>
              <Table.Th>Trigger</Table.Th>
              <Table.Th>Alerts</Table.Th>
              <Table.Th>On</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rules.data.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <SeverityBadge severity={r.severity} />
                </Table.Td>
                <Table.Td>
                  <Button variant="subtle" size="compact-sm" px={0} onClick={() => setOpen(r)}>
                    {r.title}
                  </Button>
                  <div className={classes.sub}>
                    <span className="sn-mono">{r.id}</span>
                    <span>{r.kind === "verified" ? "Verified" : "Heuristic"}, {r.confidence} confidence</span>
                  </div>
                </Table.Td>
                <Table.Td>
                  {r.threshold !== null && r.window_minutes !== null ? (
                    <span>
                      {r.threshold}+ events in {r.window_minutes} min
                    </span>
                  ) : (
                    <span>Each matching event</span>
                  )}
                  <div className={classes.sub}>
                    {r.event_actions.map((a) => (
                      <span key={a} className="sn-mono">
                        {a}
                      </span>
                    ))}
                  </div>
                </Table.Td>
                <Table.Td className="sn-num">
                  {r.open_alert_count} open
                  <Text size="xs" c="dimmed">
                    {r.alert_count} total
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Switch
                    checked={r.enabled}
                    onChange={(e) => toggle.mutate({ id: r.id, enabled: e.currentTarget.checked })}
                    aria-label={`${r.title}: ${r.enabled ? "on" : "off"}`}
                    disabled={toggle.isPending && toggle.variables?.id === r.id}
                  />
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </div>
      <Modal opened={open !== null} onClose={() => setOpen(null)} title={open?.title} size="lg">
        {open ? (
          <Stack gap="sm">
            <Group gap="xs">
              <SeverityBadge severity={open.severity} />
              <Tag>{open.kind === "verified" ? "Verified" : "Heuristic"}</Tag>
              <Tag>{humanize(open.confidence)} confidence</Tag>
            </Group>
            <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
              {open.description}
            </Text>
            <Text fw={650} size="sm">
              Investigation steps
            </Text>
            <ol className={classes.steps}>
              {open.investigation_steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
            <Text fw={650} size="sm">
              Remediation
            </Text>
            <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
              {open.remediation}
            </Text>
          </Stack>
        ) : null}
      </Modal>
    </Panel>
  );
}

function IocsTab() {
  const iocs = useIocs();
  const imp = useImportIocs();
  const del = useDeleteIoc();
  const [text, setText] = useState("");
  const parsed = parseIocText(text);
  return (
    <Stack gap="md">
      <Panel
        title="Import SHA-256 hashes"
        description={iocs.data?.note ?? "Sentinel ships no hash feed. Only hashes you import here are matched."}
      >
        <Stack gap="sm">
          <Textarea
            label="Hashes"
            description="One SHA-256 per line. Optionally add a label after a comma or space."
            placeholder={"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, example label"}
            autosize
            minRows={4}
            maxRows={12}
            value={text}
            onChange={(e) => setText(e.currentTarget.value)}
            classNames={{ input: "sn-mono" }}
          />
          {parsed.invalid.length ? (
            <Text size="xs" c="red">
              {parsed.invalid.length} line{parsed.invalid.length === 1 ? " isn't" : "s aren't"} a SHA-256 hash and will be
              skipped: {parsed.invalid.slice(0, 3).join("; ")}
            </Text>
          ) : null}
          {imp.isError ? (
            <Text size="sm" c="red" role="alert">
              {errorMessage(imp.error)}
            </Text>
          ) : null}
          <Group>
            <Button
              leftSection={<IconUpload size={16} />}
              disabled={parsed.items.length === 0}
              loading={imp.isPending}
              onClick={() =>
                imp.mutate(parsed.items, {
                  onSuccess: (r) => {
                    setText("");
                    notifications.show({ message: `${r.added} added, ${r.updated} updated. ${r.total} hashes in the list.` });
                  },
                })
              }
            >
              Import {parsed.items.length ? parsed.items.length : ""} hash{parsed.items.length === 1 ? "" : "es"}
            </Button>
          </Group>
        </Stack>
      </Panel>
      <Panel title="Imported hashes" padded={false}>
        {iocs.isPending ? <Loading /> : null}
        {iocs.isError ? <ErrorState error={iocs.error} /> : null}
        {iocs.data && iocs.data.items.length === 0 ? <Empty title="No hashes imported" /> : null}
        {iocs.data && iocs.data.items.length > 0 ? (
          <div className={classes.tableWrap}>
            <Table miw={760} mt={8}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>SHA-256</Table.Th>
                  <Table.Th>Label</Table.Th>
                  <Table.Th>Added</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {iocs.data.items.map((i) => (
                  <Table.Tr key={i.sha256}>
                    <Table.Td className="sn-mono" style={{ overflowWrap: "anywhere" }}>
                      {i.sha256}
                    </Table.Td>
                    <Table.Td>{i.label ?? <span className="sn-dim">–</span>}</Table.Td>
                    <Table.Td>
                      <Time value={i.added_at} mode="relative" />
                    </Table.Td>
                    <Table.Td>
                      <Tooltip label="Remove">
                        <Button
                          size="compact-xs"
                          variant="subtle"
                          color="red"
                          aria-label={`Remove ${i.sha256}`}
                          loading={del.isPending && del.variables === i.sha256}
                          onClick={() => del.mutate(i.sha256)}
                        >
                          <IconTrash size={14} />
                        </Button>
                      </Tooltip>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
        ) : null}
      </Panel>
    </Stack>
  );
}
