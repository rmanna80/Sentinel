import {
  Alert,
  Anchor,
  Button,
  Checkbox,
  Group,
  List,
  Menu,
  Modal,
  PasswordInput,
  Stack,
  Table,
  Tabs,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle, IconCircleCheck, IconDownload, IconLock, IconPlus, IconTrash } from "@tabler/icons-react";
import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { downloadFile, errorMessage } from "../../api/client";
import type { EmailCheckResult, IdentityOut } from "../../api/types";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { formatDay, humanize } from "../../lib/format";
import {
  fetchPwnedRange,
  useAddIdentity,
  useCheckDomain,
  useCheckIdentity,
  useDeleteIdentity,
  useDomainChecks,
  useEmailStatus,
  useIdentities,
  useIdentityHistory,
} from "./api";
import classes from "./Email.module.css";
import { checkPwnedPassword, type PwnedResult } from "./pwned";

export const OWNERSHIP_TEXT = "I own this address or am authorized to assess it";

const TABS = ["addresses", "password", "domains"] as const;

export function EmailPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab = (TABS as readonly string[]).includes(raw ?? "") ? (raw as string) : "addresses";
  const status = useEmailStatus();
  return (
    <>
      <PageHeader
        title="Email security"
        description="Whether your email addresses or passwords appear in known data breaches, using Have I Been Pwned."
      />
      {status.data ? (
        <Alert variant="light" color="gray" icon={<IconLock size={18} />} mb="md" title="What leaves this computer">
          <Text size="sm">{status.data.privacy_note}</Text>
          {!status.data.hibp_enabled || !status.data.hibp_key_configured ? (
            <Text size="sm" mt={6}>
              {status.data.tier_note}{" "}
              <Anchor component={Link} to="/integrations" size="sm">
                Set up HIBP
              </Anchor>
            </Text>
          ) : null}
        </Alert>
      ) : null}
      {status.isError ? <ErrorState error={status.error} /> : null}
      <Tabs value={tab} onChange={(v) => setParams(v && v !== "addresses" ? { tab: v } : {}, { replace: true })} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="addresses">Email addresses</Tabs.Tab>
          <Tabs.Tab value="password">Password check</Tabs.Tab>
          <Tabs.Tab value="domains">Domains</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="addresses">
          <AddressesTab />
        </Tabs.Panel>
        <Tabs.Panel value="password">
          <PasswordTab enabled={status.data?.pwned_passwords_enabled ?? true} />
        </Tabs.Panel>
        <Tabs.Panel value="domains">
          <DomainsTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

// ------------------------------------------------------------------------------------- addresses

function statusTone(s: string | null): "danger" | "good" | "neutral" | "warn" {
  if (s === "found") return "danger";
  if (s === "not_found") return "good";
  if (s === "error") return "warn";
  return "neutral";
}

const STATUS_TEXT: Record<string, string> = {
  found: "In breaches",
  not_found: "Not found",
  unavailable: "Not checked",
  error: "Check failed",
};

function AddressesTab() {
  const ids = useIdentities();
  const check = useCheckIdentity();
  const del = useDeleteIdentity();
  const [adding, setAdding] = useState(false);
  const [result, setResult] = useState<{ ident: IdentityOut; r: EmailCheckResult } | null>(null);
  const [history, setHistory] = useState<IdentityOut | null>(null);
  const [removing, setRemoving] = useState<IdentityOut | null>(null);

  return (
    <Stack gap="md">
      <Panel
        title="Monitored addresses"
        padded={false}
        actions={
          <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => setAdding(true)}>
            Add address
          </Button>
        }
      >
        {ids.isPending ? <Loading /> : null}
        {ids.isError ? <ErrorState error={ids.error} /> : null}
        {ids.data && ids.data.length === 0 ? (
          <Empty title="No addresses yet">Add an address you own to check it against known breaches.</Empty>
        ) : null}
        {check.isError ? (
          <Text c="red" size="sm" p="md" role="alert">
            {errorMessage(check.error)}
          </Text>
        ) : null}
        {ids.data && ids.data.length > 0 ? (
          <div style={{ overflowX: "auto" }}>
            <Table miw={820} mt={8}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Address</Table.Th>
                  <Table.Th>Latest result</Table.Th>
                  <Table.Th>Breaches</Table.Th>
                  <Table.Th>Last checked</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {ids.data.map((i) => (
                  <Table.Tr key={i.id}>
                    <Table.Td>
                      <div className="sn-mono">{i.email}</div>
                      {i.label ? <Text size="xs" c="dimmed">{i.label}</Text> : null}
                    </Table.Td>
                    <Table.Td>
                      {i.latest_status ? <Tag tone={statusTone(i.latest_status)}>{STATUS_TEXT[i.latest_status] ?? humanize(i.latest_status)}</Tag> : <span className="sn-dim">Never checked</span>}
                    </Table.Td>
                    <Table.Td className="sn-num">{i.breach_count === null ? <span className="sn-dim">Unknown</span> : i.breach_count}</Table.Td>
                    <Table.Td>
                      <Time value={i.last_checked_at} mode="relative" />
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4} justify="flex-end" wrap="nowrap">
                        <Button
                          size="compact-sm"
                          variant="default"
                          loading={check.isPending && check.variables === i.id}
                          onClick={() => check.mutate(i.id, { onSuccess: (r) => setResult({ ident: i, r }) })}
                        >
                          Check now
                        </Button>
                        <Button size="compact-sm" variant="subtle" onClick={() => setHistory(i)}>
                          History
                        </Button>
                        <Menu position="bottom-end">
                          <Menu.Target>
                            <Button size="compact-sm" variant="subtle" aria-label={`Download report for ${i.masked_email}`}>
                              <IconDownload size={15} />
                            </Button>
                          </Menu.Target>
                          <Menu.Dropdown>
                            <Menu.Label>Breach report</Menu.Label>
                            {(["json", "csv"] as const).map((fmt) => (
                              <Menu.Item
                                key={fmt}
                                onClick={() =>
                                  void downloadFile(`/api/email/identities/${i.id}/report`, { format: fmt }, `breach-report-${i.id}.${fmt}`).catch((err: unknown) =>
                                    notifications.show({ color: "red", message: errorMessage(err) }),
                                  )
                                }
                              >
                                {fmt.toUpperCase()}
                              </Menu.Item>
                            ))}
                          </Menu.Dropdown>
                        </Menu>
                        <Button size="compact-sm" variant="subtle" color="red" aria-label={`Stop monitoring ${i.masked_email}`} onClick={() => setRemoving(i)}>
                          <IconTrash size={15} />
                        </Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
        ) : null}
      </Panel>
      {result ? <CheckResult ident={result.ident} r={result.r} onClose={() => setResult(null)} /> : null}
      <AddIdentityDialog opened={adding} onClose={() => setAdding(false)} />
      <HistoryDialog ident={history} onClose={() => setHistory(null)} />
      <Modal opened={removing !== null} onClose={() => setRemoving(null)} title="Stop monitoring this address?" size="sm">
        <Text size="sm">{removing?.masked_email} and its check history are removed from Sentinel.</Text>
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
            Stop monitoring
          </Button>
        </Group>
      </Modal>
    </Stack>
  );
}

interface Breach {
  name: string;
  title: string;
  domain: string | null;
  breach_date: string | null;
  pwn_count: number | null;
  data_classes: string[];
  description: string | null;
  classification_label: string;
  passwords_exposed: boolean;
}

function asBreach(raw: Record<string, unknown>): Breach {
  const str = (v: unknown) => (typeof v === "string" ? v : null);
  return {
    name: str(raw.name) ?? "Unknown",
    title: str(raw.title) ?? str(raw.name) ?? "Unknown",
    domain: str(raw.domain),
    breach_date: str(raw.breach_date),
    pwn_count: typeof raw.pwn_count === "number" ? raw.pwn_count : null,
    data_classes: Array.isArray(raw.data_classes) ? raw.data_classes.filter((c): c is string => typeof c === "string") : [],
    description: str(raw.description),
    classification_label: str(raw.classification_label) ?? "",
    passwords_exposed: raw.passwords_exposed === true,
  };
}

const PRIORITY_TONE: Record<string, "danger" | "warn" | "neutral" | "accent"> = { high: "danger", medium: "warn", low: "neutral", info: "accent" };

function CheckResult({ ident, r, onClose }: { ident: IdentityOut; r: EmailCheckResult; onClose: () => void }) {
  const groups = Object.entries(r.groups).filter(([, list]) => list.length > 0);
  return (
    <Panel
      title={`Result for ${ident.masked_email}`}
      description={<Time value={r.checked_at} />}
      actions={
        <Button size="xs" variant="subtle" onClick={onClose}>
          Close
        </Button>
      }
    >
      <Stack gap="sm">
        <Alert
          variant="light"
          color={r.status === "found" ? "red" : r.status === "not_found" ? "green" : "yellow"}
          icon={r.status === "not_found" ? <IconCircleCheck size={18} /> : <IconAlertCircle size={18} />}
        >
          <Text size="sm">{r.explanation}</Text>
          {r.new_breaches.length ? (
            <Text size="sm" fw={650} mt={4}>
              New since the last check: {r.new_breaches.join(", ")}
            </Text>
          ) : null}
        </Alert>
        {r.how_to_enable?.length ? (
          <List size="sm" type="ordered">
            {r.how_to_enable.map((s) => (
              <List.Item key={s}>{s}</List.Item>
            ))}
          </List>
        ) : null}
        {r.manual_check_url ? (
          <Text size="sm">
            Check manually:{" "}
            <Anchor href={r.manual_check_url} target="_blank" rel="noopener noreferrer">
              {r.manual_check_url}
            </Anchor>
          </Text>
        ) : null}
        {r.recommendations.length ? (
          <div>
            <Text fw={650} size="sm" mb={6}>
              What to do
            </Text>
            <Stack gap={6}>
              {r.recommendations.map((rec) => (
                <Group key={rec.id} gap="sm" wrap="nowrap" align="flex-start">
                  <Tag tone={PRIORITY_TONE[rec.priority] ?? "neutral"}>{humanize(rec.priority)}</Tag>
                  <Text size="sm">{rec.text}</Text>
                </Group>
              ))}
            </Stack>
          </div>
        ) : null}
        {groups.map(([key, list]) => (
          <div key={key}>
            <Text fw={650} size="sm" mb={6}>
              {asBreach(list[0]).classification_label || humanize(key)} ({list.length})
            </Text>
            <div className={classes.breaches}>
              {list.map((raw) => {
                const b = asBreach(raw);
                return (
                  <div key={b.name} className={classes.breach}>
                    <Group justify="space-between" gap="xs">
                      <Text fw={650} size="sm">
                        {b.title}
                      </Text>
                      {b.passwords_exposed ? <Tag tone="danger">Passwords exposed</Tag> : null}
                    </Group>
                    <Text size="xs" c="dimmed">
                      {[b.domain, b.breach_date ? `breached ${formatDay(`${b.breach_date}T12:00:00Z`)}` : null, b.pwn_count ? `${b.pwn_count.toLocaleString()} accounts` : null]
                        .filter(Boolean)
                        .join(", ")}
                    </Text>
                    {b.data_classes.length ? <Text size="xs" mt={4}>Exposed: {b.data_classes.join(", ")}</Text> : null}
                    {b.description ? (
                      <Text size="xs" c="dimmed" mt={4} lineClamp={4}>
                        {b.description}
                      </Text>
                    ) : null}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
        {r.payload_summary ? (
          <Text size="xs" c="dimmed">
            Sent to HIBP: {r.payload_summary}. Logged on the Integrations page.
          </Text>
        ) : (
          <Text size="xs" c="dimmed">
            Nothing was sent anywhere for this check.
          </Text>
        )}
        {r.attribution ? (
          <Text size="xs" c="dimmed">
            {r.attribution}
          </Text>
        ) : null}
      </Stack>
    </Panel>
  );
}

function AddIdentityDialog({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const add = useAddIdentity();
  const [email, setEmail] = useState("");
  const [label, setLabel] = useState("");
  const [owned, setOwned] = useState(false);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate(
      { email: email.trim(), label: label.trim() || null, ownership_confirmed: owned },
      {
        onSuccess: () => {
          setEmail("");
          setLabel("");
          setOwned(false);
          onClose();
        },
      },
    );
  };
  return (
    <Modal opened={opened} onClose={onClose} title="Add an email address" size="md">
      <form onSubmit={submit}>
        <Stack gap="sm">
          <TextInput label="Email address" type="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} required data-autofocus autoComplete="off" />
          <TextInput label="Label" placeholder="Optional, e.g. Personal" value={label} onChange={(e) => setLabel(e.currentTarget.value)} maxLength={128} />
          <Checkbox label={OWNERSHIP_TEXT} checked={owned} onChange={(e) => setOwned(e.currentTarget.checked)} />
          <Text size="xs" c="dimmed">
            Checking sends the full address to Have I Been Pwned. Only monitor addresses you're allowed to look up.
          </Text>
          {add.isError ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(add.error)}
            </Text>
          ) : null}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!owned || !email.trim()} loading={add.isPending}>
              Add address
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function HistoryDialog({ ident, onClose }: { ident: IdentityOut | null; onClose: () => void }) {
  const hist = useIdentityHistory(ident?.id ?? null);
  return (
    <Modal opened={ident !== null} onClose={onClose} title={`Check history: ${ident?.masked_email ?? ""}`} size="lg">
      {hist.isPending ? <Loading /> : null}
      {hist.isError ? <ErrorState error={hist.error} /> : null}
      {hist.data && hist.data.length === 0 ? <Text size="sm" c="dimmed">Not checked yet.</Text> : null}
      {hist.data && hist.data.length > 0 ? (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>When</Table.Th>
              <Table.Th>Result</Table.Th>
              <Table.Th>Breaches</Table.Th>
              <Table.Th>Note</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {hist.data.map((h) => (
              <Table.Tr key={h.id}>
                <Table.Td>
                  <Time value={h.checked_at} />
                </Table.Td>
                <Table.Td>
                  <Tag tone={statusTone(h.status)}>{STATUS_TEXT[h.status] ?? humanize(h.status)}</Tag>
                </Table.Td>
                <Table.Td className="sn-num">{h.breach_count}</Table.Td>
                <Table.Td>
                  <Text size="xs">{h.error ?? ""}</Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      ) : null}
    </Modal>
  );
}

// ------------------------------------------------------------------------------------- password

function PasswordTab({ enabled }: { enabled: boolean }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PwnedResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!password) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await checkPwnedPassword(password, fetchPwnedRange));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPassword("");
      setBusy(false);
    }
  };
  return (
    <Panel
      title="Is this password in a known breach?"
      description="Your browser hashes the password and sends only the first 5 characters of the hash. Sentinel's server and Have I Been Pwned never see the password or its full hash; the match happens on this page."
    >
      <form onSubmit={(e) => void submit(e)}>
        <Stack gap="sm" maw={460}>
          {!enabled ? (
            <Alert color="yellow" variant="light">
              Pwned Passwords is turned off on the Integrations page.
            </Alert>
          ) : null}
          <PasswordInput
            label="Password"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
            autoComplete="off"
            description="Cleared as soon as the check runs. Never stored."
          />
          <Group>
            <Button type="submit" loading={busy} disabled={!password || !enabled}>
              Check password
            </Button>
          </Group>
          {error ? (
            <Text c="red" size="sm" role="alert">
              {error}
            </Text>
          ) : null}
          {result ? (
            <Alert
              role="status"
              variant="light"
              color={result.count > 0 ? "red" : "green"}
              icon={result.count > 0 ? <IconAlertCircle size={18} /> : <IconCircleCheck size={18} />}
              title={result.count > 0 ? "Found in breaches" : "Not found"}
            >
              <Text size="sm">
                {result.count > 0
                  ? `This password appears ${result.count.toLocaleString()} time${result.count === 1 ? "" : "s"} in breach data. Stop using it anywhere, and change it on every account that uses it.`
                  : "This password isn't in Pwned Passwords. That doesn't make it strong: use a long, unique password for each account."}
              </Text>
              <Text size="xs" c="dimmed" mt={4}>
                Sent: <span className="sn-mono">{result.prefixSent}</span> (first 5 characters of the SHA-1 hash).
              </Text>
            </Alert>
          ) : null}
        </Stack>
      </form>
    </Panel>
  );
}

// ------------------------------------------------------------------------------------- domains

function DomainsTab() {
  const checks = useDomainChecks();
  const check = useCheckDomain();
  const [domain, setDomain] = useState("");
  const r = check.data;
  return (
    <Stack gap="md">
      <Panel
        title="Check a domain"
        description="Finds breached addresses on a whole domain. HIBP only searches domains you've verified you control, with the same account as the API key."
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (domain.trim()) check.mutate(domain.trim());
          }}
        >
          <Group align="flex-end" gap="sm">
            <TextInput label="Domain" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.currentTarget.value)} w={280} />
            <Button type="submit" loading={check.isPending} disabled={!domain.trim()}>
              Check domain
            </Button>
          </Group>
        </form>
        {check.isError ? (
          <Text c="red" size="sm" mt="sm" role="alert">
            {errorMessage(check.error)}
          </Text>
        ) : null}
        {r ? (
          <Stack gap="xs" mt="md">
            <Alert variant="light" color={r.status === "found" ? "red" : r.status === "not_found" ? "green" : "yellow"}>
              <Text size="sm">{r.explanation}</Text>
            </Alert>
            {r.verification_methods?.length ? (
              <List size="sm">
                {r.verification_methods.map((m) => (
                  <List.Item key={m}>{m}</List.Item>
                ))}
              </List>
            ) : null}
            {r.attribution ? <Text size="xs" c="dimmed">{r.attribution}</Text> : null}
          </Stack>
        ) : null}
      </Panel>
      <Panel title="Recent domain checks" padded={false}>
        {checks.isPending ? <Loading /> : null}
        {checks.data && checks.data.length === 0 ? <Empty title="No domain checks yet" /> : null}
        {checks.data && checks.data.length > 0 ? (
          <Table mt={8}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Domain</Table.Th>
                <Table.Th>Result</Table.Th>
                <Table.Th>When</Table.Th>
                <Table.Th>Note</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {checks.data.map((d) => (
                <Table.Tr key={d.id}>
                  <Table.Td className="sn-mono">{d.domain}</Table.Td>
                  <Table.Td>
                    <Tag tone={statusTone(d.status)}>{STATUS_TEXT[d.status] ?? humanize(d.status)}</Tag>
                  </Table.Td>
                  <Table.Td>
                    <Time value={d.checked_at} mode="relative" />
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs">
                      {d.error ??
                        (typeof d.result.alias_count === "number" ? `${d.result.alias_count} breached address(es)` : "")}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        ) : null}
      </Panel>
    </Stack>
  );
}
