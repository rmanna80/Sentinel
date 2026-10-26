import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle, IconKey, IconRefresh, IconTrash } from "@tabler/icons-react";
import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { IntelSourceStatus, SecretStatus } from "../../api/types";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { formatDuration, humanize } from "../../lib/format";
import type { IntegrationSettings, IntegrationToggle } from "../settings/api";
import { useIntelStatus, useIntelSync } from "../vulnerabilities/api";
import { useAppSettings, useDeleteSecret, useOutbound, useSaveSetting, useSecrets, useSetSecret } from "./api";
import classes from "./Integrations.module.css";

const INTEGRATIONS: Record<string, { label: string; sends: string; purpose: string }> = {
  osv: { label: "OSV.dev", sends: "Package names and versions of installed software", purpose: "Known vulnerabilities in open-source packages" },
  nvd: { label: "NVD (NIST)", sends: "Product identifiers only, no device data", purpose: "CVE details and CVSS scores" },
  kev: { label: "CISA KEV", sends: "Nothing (downloads a public list)", purpose: "Which vulnerabilities are being exploited" },
  epss: { label: "EPSS (FIRST)", sends: "CVE identifiers only", purpose: "How likely a vulnerability is to be exploited soon" },
  msrc: { label: "Microsoft Security Response Center", sends: "Nothing (downloads public update documents)", purpose: "Windows security updates" },
  hibp: { label: "Have I Been Pwned", sends: "The full email address you ask about", purpose: "Breach lookups for monitored addresses (API key needed)" },
  pwned_passwords: { label: "Pwned Passwords", sends: "First 5 characters of a password's SHA-1 hash, computed in your browser", purpose: "Whether a password appears in known breaches" },
  ollama: { label: "Ollama (local AI model)", sends: "Nothing leaves this computer: Ollama runs on 127.0.0.1", purpose: "The AI security assistant" },
};

const SECRETS: Record<string, { label: string; help: string }> = {
  hibp_api_key: { label: "Have I Been Pwned API key", help: "Needed for email breach lookups. Get one at haveibeenpwned.com/API/Key." },
  nvd_api_key: { label: "NVD API key", help: "Optional. Raises NVD's rate limit; lookups work without it, just slower." },
  smtp_password: { label: "SMTP password", help: "For the email digest, if your mail server needs a login." },
};

const TABS = ["sources", "secrets", "outbound"] as const;

export function IntegrationsPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab = (TABS as readonly string[]).includes(raw ?? "") ? (raw as string) : "sources";
  return (
    <>
      <PageHeader
        title="Integrations"
        description="The outside services Sentinel may contact, the keys they use, and a log of every request it made."
      />
      <Tabs value={tab} onChange={(v) => setParams(v && v !== "sources" ? { tab: v } : {}, { replace: true })} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="sources">Services</Tabs.Tab>
          <Tabs.Tab value="secrets">API keys and passwords</Tabs.Tab>
          <Tabs.Tab value="outbound">Outbound data log</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="sources">
          <Stack gap="md">
            <TogglesPanel />
            <IntelPanel />
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="secrets">
          <SecretsPanel />
        </Tabs.Panel>
        <Tabs.Panel value="outbound">
          <OutboundPanel />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

function TogglesPanel() {
  const settings = useAppSettings();
  const save = useSaveSetting("integrations");
  const [ollama, setOllama] = useState({ url: "", model: "" });
  const integrations: IntegrationSettings = settings.data?.integrations ?? {};
  const o = integrations.ollama;

  useEffect(() => {
    if (o) setOllama({ url: typeof o.url === "string" ? o.url : "", model: typeof o.model === "string" ? o.model : "" });
  }, [o]);

  if (settings.isPending) return <Loading />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;

  const toggle = (name: string, current: IntegrationToggle, enabled: boolean) =>
    save.mutate(
      { [name]: { ...current, enabled } },
      {
        onSuccess: () =>
          notifications.show({ message: `${INTEGRATIONS[name]?.label ?? name} turned ${enabled ? "on" : "off"}` }),
      },
    );

  const names = Object.keys(integrations).sort(
    (a, b) => Object.keys(INTEGRATIONS).indexOf(a) - Object.keys(INTEGRATIONS).indexOf(b),
  );

  return (
    <Panel title="Services" description="Each is used only when it's on. Turning one off stops all requests to it." padded={false}>
      {save.isError ? (
        <Alert color="red" variant="light" icon={<IconAlertCircle size={18} />} m="md" role="alert">
          {errorMessage(save.error)}
        </Alert>
      ) : null}
      <div style={{ overflowX: "auto" }}>
        <Table miw={760} mt={8}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Service</Table.Th>
              <Table.Th>Used for</Table.Th>
              <Table.Th>What leaves this computer</Table.Th>
              <Table.Th>On</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {names.map((name) => {
              const meta = INTEGRATIONS[name] ?? { label: humanize(name), sends: "See the outbound log", purpose: "" };
              const cur = integrations[name];
              return (
                <Table.Tr key={name}>
                  <Table.Td fw={600}>{meta.label}</Table.Td>
                  <Table.Td>{meta.purpose}</Table.Td>
                  <Table.Td>{meta.sends}</Table.Td>
                  <Table.Td>
                    <Switch
                      checked={cur.enabled}
                      onChange={(e) => toggle(name, cur, e.currentTarget.checked)}
                      aria-label={`${meta.label}: ${cur.enabled ? "on" : "off"}`}
                      disabled={save.isPending}
                    />
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </div>
      {o ? (
        <form
          className={classes.ollama}
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            save.mutate(
              { ollama: { ...o, url: ollama.url.trim(), model: ollama.model.trim() } },
              { onSuccess: () => notifications.show({ message: "Ollama settings saved" }) },
            );
          }}
        >
          <Text fw={650} size="sm">
            Ollama connection
          </Text>
          <Text size="xs" c="dimmed" mb="xs">
            The address must be on this computer (127.0.0.1 or localhost). Sentinel refuses anything else.
          </Text>
          <Group align="flex-end" gap="sm">
            <TextInput label="Address" value={ollama.url} onChange={(e) => setOllama((s) => ({ ...s, url: e.currentTarget.value }))} w={260} />
            <TextInput label="Model" value={ollama.model} onChange={(e) => setOllama((s) => ({ ...s, model: e.currentTarget.value }))} w={200} />
            <Button type="submit" variant="default" loading={save.isPending}>
              Save
            </Button>
          </Group>
        </form>
      ) : null}
    </Panel>
  );
}

const SYNC_TONE: Record<string, "good" | "danger" | "neutral" | "warn"> = { ok: "good", error: "danger", never: "neutral", disabled: "neutral" };

function IntelPanel() {
  const intel = useIntelStatus();
  const sync = useIntelSync();
  if (intel.isPending) return <Loading label="Loading vulnerability data sources" />;
  if (intel.isError) return <ErrorState error={intel.error} title="Vulnerability data sources unavailable" />;
  const s = intel.data;
  const run = (source: IntelSourceStatus["source"] | "all") =>
    sync.mutate(
      { source: source as "osv" | "nvd" | "msrc" | "kev" | "epss" | "all" },
      { onSuccess: (r) => notifications.show({ message: r.message }) },
    );
  return (
    <Panel
      title="Vulnerability data"
      description="Public data Sentinel downloads to match installed software. Syncs run in the background; you can request one now."
      actions={
        <Button size="xs" variant="default" leftSection={<IconRefresh size={14} />} onClick={() => run("all")} loading={sync.isPending && sync.variables?.source === "all"} disabled={!s.outbound_enabled}>
          Sync all
        </Button>
      }
      padded={false}
    >
      {!s.outbound_enabled ? (
        <Alert color="yellow" variant="light" m="md" icon={<IconAlertCircle size={18} />}>
          Outbound connections are turned off for this server (SENTINEL_OUTBOUND_ENABLED). Nothing is downloaded.
        </Alert>
      ) : null}
      {sync.isError ? (
        <Alert color="red" variant="light" m="md" role="alert">
          {errorMessage(sync.error)}
        </Alert>
      ) : null}
      <div style={{ overflowX: "auto" }}>
        <Table miw={760} mt={8}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Source</Table.Th>
              <Table.Th>State</Table.Th>
              <Table.Th>Last synced</Table.Th>
              <Table.Th>Notes</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {s.sources.map((src) => (
              <Table.Tr key={src.source}>
                <Table.Td fw={600}>{src.label}</Table.Td>
                <Table.Td>
                  <Tag tone={src.enabled ? (SYNC_TONE[src.status] ?? "neutral") : "neutral"}>
                    {src.enabled ? humanize(src.status) : "Off"}
                  </Tag>
                  {src.sync_requested ? (
                    <Text size="xs" c="dimmed" mt={3}>
                      Sync requested
                    </Text>
                  ) : null}
                </Table.Td>
                <Table.Td>
                  <Time value={src.last_synced_at} mode="relative" />
                </Table.Td>
                <Table.Td>
                  <Text size="xs">{src.detail ?? ""}</Text>
                  {src.rate_limit ? (
                    <Text size="xs" c="dimmed">
                      {src.rate_limit}
                    </Text>
                  ) : null}
                  {src.api_key_configured === false ? (
                    <Text size="xs" c="dimmed">
                      No API key (optional)
                    </Text>
                  ) : null}
                </Table.Td>
                <Table.Td>
                  {["osv", "nvd", "msrc", "kev", "epss"].includes(src.source) ? (
                    <Button
                      size="compact-xs"
                      variant="subtle"
                      disabled={!src.enabled || !s.outbound_enabled}
                      loading={sync.isPending && sync.variables?.source === src.source}
                      onClick={() => run(src.source)}
                    >
                      Sync
                    </Button>
                  ) : null}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </div>
      <Group gap="xl" p="md" className={classes.intelFoot}>
        <Text size="xs" c="dimmed">
          Queue: {s.queue.waiting} waiting, {s.queue.retrying} retrying
          {s.queue.last_error ? `. Last error: ${s.queue.last_error}` : ""}
        </Text>
        <Text size="xs" c="dimmed">
          KEV catalog: {s.kev_catalog_version ?? "not downloaded"}
          {s.kev_count !== null ? ` (${s.kev_count.toLocaleString()} entries)` : ""}
        </Text>
        <Text size="xs" c="dimmed">
          NVD products cached: {s.nvd_products_cached}
        </Text>
        <Text size="xs" c="dimmed">
          MSRC documents: {s.msrc_documents.length ? s.msrc_documents.join(", ") : "none"}
        </Text>
      </Group>
    </Panel>
  );
}

function backendLabel(backend: string): string {
  return backend === "file"
    ? "a private file in Sentinel's data folder (no OS credential store is available)"
    : `the operating system's credential store (${backend})`;
}

function SecretsPanel() {
  const secrets = useSecrets();
  const [editing, setEditing] = useState<SecretStatus | null>(null);
  const [removing, setRemoving] = useState<SecretStatus | null>(null);
  const del = useDeleteSecret();
  if (secrets.isPending) return <Loading />;
  if (secrets.isError) return <ErrorState error={secrets.error} onRetry={() => void secrets.refetch()} />;
  const backend = secrets.data[0]?.backend;
  return (
    <Panel
      title="API keys and passwords"
      description={
        backend
          ? `Stored in ${backendLabel(backend)}. Stored values are never shown again, not even to you; you can only replace or remove them.`
          : undefined
      }
      padded={false}
    >
      {backend === "file" ? (
        <Alert color="yellow" variant="light" m="md" icon={<IconAlertCircle size={18} />}>
          No OS credential store is available, so secrets go in a file only your user account can read. That's weaker than
          Windows Credential Manager: anyone with access to your account can read it.
        </Alert>
      ) : null}
      <Table mt={8}>
        <Table.Tbody>
          {secrets.data.map((s) => (
            <Table.Tr key={s.name}>
              <Table.Td>
                <Text fw={600} size="sm">
                  {SECRETS[s.name]?.label ?? s.name}
                </Text>
                <Text size="xs" c="dimmed">
                  {SECRETS[s.name]?.help} <span className="sn-mono">({s.name})</span>
                </Text>
              </Table.Td>
              <Table.Td w={130}>
                {s.configured ? <Badge color="green" variant="light">Stored</Badge> : <Badge color="gray" variant="light">Not set</Badge>}
              </Table.Td>
              <Table.Td w={220}>
                <Group gap={6} justify="flex-end">
                  <Button size="xs" variant="default" leftSection={<IconKey size={14} />} onClick={() => setEditing(s)}>
                    {s.configured ? "Replace" : "Set"}
                  </Button>
                  {s.configured ? (
                    <Button size="xs" variant="subtle" color="red" leftSection={<IconTrash size={14} />} onClick={() => setRemoving(s)}>
                      Remove
                    </Button>
                  ) : null}
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
      <SecretDialog secret={editing} onClose={() => setEditing(null)} />
      <Modal opened={removing !== null} onClose={() => setRemoving(null)} title="Remove this secret?" size="sm">
        <Text size="sm">
          {removing ? SECRETS[removing.name]?.label ?? removing.name : ""} will be deleted. Features that need it stop until you
          set it again.
        </Text>
        {del.isError ? (
          <Text c="red" size="sm" mt="sm" role="alert">
            {errorMessage(del.error)}
          </Text>
        ) : null}
        <Group justify="flex-end" mt="md">
          <Button variant="default" onClick={() => setRemoving(null)}>
            Keep it
          </Button>
          <Button
            color="red"
            loading={del.isPending}
            onClick={() => removing && del.mutate(removing.name, { onSuccess: () => setRemoving(null) })}
          >
            Remove
          </Button>
        </Group>
      </Modal>
    </Panel>
  );
}

function SecretDialog({ secret, onClose }: { secret: SecretStatus | null; onClose: () => void }) {
  const set = useSetSecret();
  const [value, setValue] = useState("");
  useEffect(() => {
    setValue("");
    set.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [secret?.name]);
  return (
    <Modal opened={secret !== null} onClose={onClose} title={secret ? (SECRETS[secret.name]?.label ?? secret.name) : ""} size="md">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!secret || !value.trim()) return;
          set.mutate(
            { name: secret.name, value },
            {
              onSuccess: () => {
                setValue("");
                notifications.show({ message: "Saved. The value won't be shown again." });
                onClose();
              },
            },
          );
        }}
      >
        <Stack gap="sm">
          <PasswordInput
            label="Value"
            description="Sent once to the server on this computer and stored; never displayed again."
            value={value}
            onChange={(e) => setValue(e.currentTarget.value)}
            autoComplete="off"
            maxLength={512}
            required
            data-autofocus
          />
          {set.isError ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(set.error)}
            </Text>
          ) : null}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={set.isPending} disabled={!value.trim()}>
              Save
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function OutboundPanel() {
  const [integration, setIntegration] = useState<string | null>(null);
  const [page, setPage] = useState({ limit: 50, offset: 0 });
  const log = useOutbound({ integration: integration ?? undefined, ...page });
  return (
    <Panel
      title="Outbound data log"
      description="Every request Sentinel's server made to the internet, with what was sent. Personal values (like an email address in a URL) are left out of the recorded path."
      padded={false}
    >
      <Group p="md" pt="sm" gap="sm">
        <Select
          size="xs"
          label="Service"
          w={240}
          data={[{ value: "", label: "All services" }, ...Object.entries(INTEGRATIONS).map(([value, m]) => ({ value, label: m.label }))]}
          value={integration ?? ""}
          onChange={(v) => {
            setIntegration(v || null);
            setPage((p) => ({ ...p, offset: 0 }));
          }}
        />
      </Group>
      {log.isPending ? <Loading /> : null}
      {log.isError ? <ErrorState error={log.error} /> : null}
      {log.data && log.data.items.length === 0 ? (
        <Empty title="No outbound requests recorded">
          Nothing has been sent to the internet{integration ? " by this service" : ""}. Requests appear here as soon as a
          sync or lookup runs.
        </Empty>
      ) : null}
      {log.data && log.data.items.length > 0 ? (
        <>
          <div style={{ overflowX: "auto" }}>
            <Table miw={1000}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>When</Table.Th>
                  <Table.Th>Service</Table.Th>
                  <Table.Th>Request</Table.Th>
                  <Table.Th>Purpose</Table.Th>
                  <Table.Th>What was sent</Table.Th>
                  <Table.Th>Result</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {log.data.items.map((r) => (
                  <Table.Tr key={r.id}>
                    <Table.Td>
                      <Time value={typeof r.ts === "string" ? r.ts : null} />
                    </Table.Td>
                    <Table.Td>{INTEGRATIONS[r.integration]?.label ?? r.integration}</Table.Td>
                    <Table.Td>
                      <span className="sn-mono" style={{ overflowWrap: "anywhere" }}>
                        {r.method} {r.host}
                        {r.path}
                      </span>
                    </Table.Td>
                    <Table.Td>{r.purpose}</Table.Td>
                    <Table.Td>{r.payload_summary}</Table.Td>
                    <Table.Td>
                      {r.error ? (
                        <Text size="xs" c="red">
                          {r.error}
                        </Text>
                      ) : (
                        <span className="sn-num">HTTP {r.status_code ?? "?"}</span>
                      )}
                      {r.duration_ms !== null ? (
                        <Text size="xs" c="dimmed">
                          {formatDuration(r.duration_ms)}
                        </Text>
                      ) : null}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
          <Pager total={log.data.total} limit={page.limit} offset={page.offset} onChange={setPage} pageSizes={[50, 100, 200]} />
        </>
      ) : null}
    </Panel>
  );
}
