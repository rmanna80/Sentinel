import { Alert, Button, Group, Modal, Select, Stack, Switch, Table, Tabs, Text, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconPlus, IconRadar, IconTrash } from "@tabler/icons-react";
import { useState, type FormEvent } from "react";
import { useSearchParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { NetworkFact, ScopeCreate, ScopeOut } from "../../api/types";
import { DemoBadge, isFixture } from "../../components/DemoData";
import { JsonView } from "../../components/JsonView";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { RowLink } from "../../components/RowLink";
import { SeverityBadge } from "../../components/Severity";
import { StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "../devices/api";
import { requiredSentence, useAddScope, useDeleteScope, useNetworkSummary, useScope, useUpdateScope } from "./api";
import classes from "./Network.module.css";
import { NetworkScanDialog } from "./NetworkScanDialog";

const FACT_TITLES: Record<string, string> = {
  "net.listening": "Listening ports",
  "net.interfaces": "Network interfaces",
  "net.dns_config": "DNS configuration",
  "win.network_profile": "Windows network profile",
};

export function NetworkPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "scope" ? "scope" : "summary";
  const { deviceId } = useDeviceScope();
  const [scanOpen, setScanOpen] = useState(false);
  return (
    <>
      <PageHeader
        title="Network security"
        description="What each device exposes on the network, and scans of other systems you're authorized to test. Nothing is scanned outside the scope you set."
        actions={
          <Button leftSection={<IconRadar size={16} />} onClick={() => setScanOpen(true)}>
            New network scan
          </Button>
        }
      />
      <Tabs value={tab} onChange={(v) => setParams(v === "scope" ? { tab: "scope" } : {}, { replace: true })} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="summary">Device exposure</Tabs.Tab>
          <Tabs.Tab value="scope">Scan scope</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="summary">
          <SummaryTab />
        </Tabs.Panel>
        <Tabs.Panel value="scope">
          <ScopeTab />
        </Tabs.Panel>
      </Tabs>
      <NetworkScanDialog opened={scanOpen} onClose={() => setScanOpen(false)} deviceId={deviceId} />
    </>
  );
}

function SummaryTab() {
  const { deviceId: scoped } = useDeviceScope();
  const devices = useDevices();
  const [picked, setPicked] = useState<number | null>(null);
  const deviceId = scoped ?? picked ?? devices.data?.[0]?.id ?? null;
  const summary = useNetworkSummary(deviceId);
  return (
    <Stack gap="md">
      {scoped === null ? (
        <Select
          label="Device"
          w={260}
          data={(devices.data ?? []).map((d) => ({ value: String(d.id), label: d.name }))}
          value={deviceId ? String(deviceId) : null}
          onChange={(v) => setPicked(v ? Number(v) : null)}
        />
      ) : null}
      {devices.data && devices.data.length === 0 ? <Empty title="No devices enrolled" /> : null}
      {summary.isPending && deviceId !== null ? <Loading /> : null}
      {summary.isError ? <ErrorState error={summary.error} /> : null}
      {summary.data ? (
        <>
          <div className={classes.factGrid}>
            {Object.entries(summary.data.facts).map(([checkId, fact]) => (
              <FactPanel key={checkId} checkId={checkId} fact={fact ?? null} />
            ))}
          </div>
          <Panel title="Open network findings" padded={false}>
            {summary.data.findings.length === 0 ? (
              <Text size="sm" c="dimmed" p="md">
                None open.
              </Text>
            ) : (
              <Table mt={8}>
                <Table.Tbody>
                  {summary.data.findings.map((f) => (
                    <Table.Tr key={f.id}>
                      <Table.Td w={110}>
                        <SeverityBadge severity={f.severity} />
                      </Table.Td>
                      <Table.Td>
                        <RowLink to={`/vulnerabilities/${f.id}`}>{f.title}</RowLink>
                      </Table.Td>
                      <Table.Td w={130}>
                        <StatusBadge kind="finding" value={f.status} />
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
          </Panel>
          <Panel title="Recent network scans" padded={false}>
            {summary.data.scans.length === 0 ? (
              <Text size="sm" c="dimmed" p="md">
                No network scans from this device yet.
              </Text>
            ) : (
              <Table mt={8}>
                <Table.Tbody>
                  {summary.data.scans.map((s) => (
                    <Table.Tr key={s.id}>
                      <Table.Td>
                        <RowLink to={`/scans/${s.id}`}>Scan {s.id}</RowLink> {isFixture(s.data_mode) ? <DemoBadge /> : null}
                        <Text size="xs" c="dimmed" className="sn-mono">
                          {(s.check_ids ?? []).join(", ")}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <StatusBadge kind="scan" value={s.status} />
                      </Table.Td>
                      <Table.Td>
                        <Time value={s.requested_at} mode="relative" />
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
          </Panel>
        </>
      ) : null}
    </Stack>
  );
}

function FactPanel({ checkId, fact }: { checkId: string; fact: NetworkFact | null }) {
  const title = FACT_TITLES[checkId] ?? fact?.title ?? checkId;
  return (
    <Panel
      title={title}
      description={
        fact ? (
          <>
            From <RowLink to={`/scans/${fact.scan_id}`}>scan {fact.scan_id}</RowLink>, <Time value={fact.finished_at} mode="relative" />
          </>
        ) : undefined
      }
    >
      {!fact ? (
        <Text size="sm" c="dimmed">
          Not collected yet. A full or posture scan on this device collects it (if the check applies to its OS).
        </Text>
      ) : fact.evidence.length === 0 ? (
        <Text size="sm" c="dimmed">
          The check ran but stored no evidence.
        </Text>
      ) : (
        <Stack gap="xs">
          {fact.evidence.map((e, i) => (
            <div key={i}>
              <Group gap={8} mb={4}>
                <Tag>{humanize(e.kind)}</Tag>
                <Text size="xs" c="dimmed" className="sn-mono">
                  {e.source}
                </Text>
                {e.redacted ? <Tag tone="warn">Redacted</Tag> : null}
              </Group>
              <JsonView value={e.content} maxHeight={240} />
            </div>
          ))}
        </Stack>
      )}
    </Panel>
  );
}

function ScopeTab() {
  const scope = useScope();
  const update = useUpdateScope();
  const del = useDeleteScope();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<ScopeOut | null>(null);
  return (
    <Panel
      title="Scan scope"
      description="Network scans may only reach these networks, hosts and URLs. Public addresses need a typed authorization. The server never resolves names: a hostname is in scope only if it's listed itself."
      padded={false}
      actions={
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => setAdding(true)}>
          Add to scope
        </Button>
      }
    >
      {scope.isPending ? <Loading /> : null}
      {scope.isError ? <ErrorState error={scope.error} /> : null}
      {scope.data && scope.data.length === 0 ? (
        <Empty title="Nothing is in scope">Add your home network (for example 192.168.1.0/24) to allow scans of it.</Empty>
      ) : null}
      {update.isError ? (
        <Text c="red" size="sm" p="md" role="alert">
          {errorMessage(update.error)}
        </Text>
      ) : null}
      {scope.data && scope.data.length > 0 ? (
        <div style={{ overflowX: "auto" }}>
          <Table miw={760} mt={8}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Target</Table.Th>
                <Table.Th>Kind</Table.Th>
                <Table.Th>Note</Table.Th>
                <Table.Th>Added</Table.Th>
                <Table.Th>Enabled</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {scope.data.map((e) => (
                <Table.Tr key={e.id}>
                  <Table.Td>
                    <span className="sn-mono">{e.value}</span>
                    {e.is_public ? (
                      <Text size="xs" c="dimmed">
                        Public. Authorization: “{e.authorization}”
                      </Text>
                    ) : null}
                  </Table.Td>
                  <Table.Td>
                    <Tag tone={e.is_public ? "warn" : "neutral"}>
                      {e.kind === "cidr" ? "Network" : e.kind === "host" ? "Host" : "URL"}
                      {e.is_public ? ", public" : ""}
                    </Tag>
                  </Table.Td>
                  <Table.Td>{e.note ?? <span className="sn-dim">–</span>}</Table.Td>
                  <Table.Td>
                    <Time value={e.created_at} mode="relative" />
                  </Table.Td>
                  <Table.Td>
                    <Switch checked={e.enabled} aria-label={`${e.value} enabled`} onChange={(ev) => update.mutate({ id: e.id, body: { enabled: ev.currentTarget.checked } })} />
                  </Table.Td>
                  <Table.Td>
                    <Button size="compact-sm" variant="subtle" color="red" aria-label={`Remove ${e.value}`} onClick={() => setRemoving(e)}>
                      <IconTrash size={15} />
                    </Button>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </div>
      ) : null}
      <AddScopeDialog opened={adding} onClose={() => setAdding(false)} />
      <Modal opened={removing !== null} onClose={() => setRemoving(null)} title="Remove from scope?" size="sm">
        <Text size="sm">Scans of {removing?.value} won't be allowed any more. Past scan results are kept.</Text>
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
            Remove
          </Button>
        </Group>
      </Modal>
    </Panel>
  );
}

function AddScopeDialog({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const add = useAddScope();
  const [kind, setKind] = useState<ScopeCreate["kind"]>("cidr");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [sentence, setSentence] = useState<string | null>(null);
  const [typed, setTyped] = useState("");

  const reset = () => {
    setValue("");
    setNote("");
    setSentence(null);
    setTyped("");
    add.reset();
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate(
      { kind, value: value.trim(), note: note.trim() || null, confirm_public: sentence ? typed : null },
      {
        onSuccess: (entry) => {
          notifications.show({ message: `${entry.value} added to the scope` });
          reset();
          onClose();
        },
        onError: (err) => {
          const needed = requiredSentence(errorMessage(err));
          if (needed) setSentence(needed);
        },
      },
    );
  };

  const errorText = add.isError ? errorMessage(add.error) : null;
  return (
    <Modal
      opened={opened}
      onClose={() => {
        reset();
        onClose();
      }}
      title="Add to scan scope"
      size="md"
    >
      <form onSubmit={submit}>
        <Stack gap="sm">
          <Select
            label="Kind"
            data={[
              { value: "cidr", label: "Network range (CIDR), e.g. 192.168.1.0/24" },
              { value: "host", label: "Single host (IP address or name)" },
              { value: "url", label: "URL (for HTTP header checks)" },
            ]}
            value={kind}
            onChange={(v) => {
              setKind((v ?? "cidr") as ScopeCreate["kind"]);
              setSentence(null);
            }}
          />
          <TextInput
            label="Target"
            value={value}
            onChange={(e) => {
              setValue(e.currentTarget.value);
              setSentence(null);
              setTyped("");
            }}
            classNames={{ input: "sn-mono" }}
            required
            data-autofocus
          />
          <TextInput label="Note" placeholder="Optional, e.g. Home network" value={note} onChange={(e) => setNote(e.currentTarget.value)} maxLength={300} />
          {sentence ? (
            <Alert color="yellow" variant="light" title="This is a public target">
              <Text size="sm">
                Scanning systems you aren't authorized to test may be illegal. To add it, type this sentence exactly:
              </Text>
              <Text size="sm" fw={700} mt={6} className="sn-mono">
                {sentence}
              </Text>
              <TextInput
                mt="sm"
                aria-label="Authorization sentence"
                value={typed}
                onChange={(e) => setTyped(e.currentTarget.value)}
                autoComplete="off"
                onPaste={(e) => e.preventDefault()}
                error={typed && typed !== sentence ? "Type it exactly as shown." : undefined}
              />
            </Alert>
          ) : null}
          {errorText && !sentence ? (
            <Text c="red" size="sm" role="alert">
              {errorText}
            </Text>
          ) : null}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => { reset(); onClose(); }}>
              Cancel
            </Button>
            <Button type="submit" loading={add.isPending} disabled={!value.trim() || (sentence !== null && typed !== sentence)}>
              Add to scope
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
