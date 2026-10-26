import {
  Alert,
  Anchor,
  Button,
  Group,
  NumberInput,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle, IconCircleCheck, IconCircleX, IconMail, IconShieldCheck } from "@tabler/icons-react";
import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { AuditEntry } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { passwordIssues } from "../../auth/AuthScreens";
import { JsonView } from "../../components/JsonView";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { useTestEmail } from "../notifications/api";
import {
  useAppSettings,
  useAudit,
  useChangePassword,
  useSaveSetting,
  useVerifyAudit,
  type NotificationSettings,
  type RetentionSettings,
} from "./api";
import classes from "./Settings.module.css";

const TABS = ["audit", "notifications", "retention", "account"] as const;
type Tab = (typeof TABS)[number];

export function SettingsPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab: Tab = (TABS as readonly string[]).includes(raw ?? "") ? (raw as Tab) : "audit";
  return (
    <>
      <PageHeader title="Settings and audit" description="Who did what, notification and retention settings, and your account." />
      <Tabs value={tab} onChange={(v) => setParams(v && v !== "audit" ? { tab: v } : {}, { replace: true })} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="audit">Audit log</Tabs.Tab>
          <Tabs.Tab value="notifications">Notifications</Tabs.Tab>
          <Tabs.Tab value="retention">Data retention</Tabs.Tab>
          <Tabs.Tab value="account">Account</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="audit">
          <AuditTab />
        </Tabs.Panel>
        <Tabs.Panel value="notifications">
          <NotificationsTab />
        </Tabs.Panel>
        <Tabs.Panel value="retention">
          <RetentionTab />
        </Tabs.Panel>
        <Tabs.Panel value="account">
          <AccountTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

// ------------------------------------------------------------------------------------------ audit

function AuditTab() {
  const [actionInput, setActionInput] = useState("");
  const [actorInput, setActorInput] = useState("");
  const [action] = useDebouncedValue(actionInput.trim(), 300);
  const [actor] = useDebouncedValue(actorInput.trim(), 300);
  const [page, setPage] = useState({ limit: 50, offset: 0 });
  const [expanded, setExpanded] = useState<number | null>(null);
  useEffect(() => setPage((p) => ({ ...p, offset: 0 })), [action, actor]);
  const audit = useAudit({ action: action || undefined, actor: actor || undefined, ...page });
  const verify = useVerifyAudit();

  return (
    <Stack gap="md">
      <Panel
        title="Tamper check"
        description="Each audit entry includes a hash of the one before it. Verifying recomputes the whole chain, so an edited or deleted entry shows up as a break."
        actions={
          <Button size="xs" variant="default" leftSection={<IconShieldCheck size={14} />} loading={verify.isPending} onClick={() => verify.mutate()}>
            Verify chain
          </Button>
        }
      >
        {verify.isError ? <ErrorState error={verify.error} /> : null}
        {verify.data ? (
          verify.data.intact ? (
            <Alert color="green" variant="light" icon={<IconCircleCheck size={18} />} title="Chain intact" role="status">
              All {verify.data.entries.toLocaleString()} entries match their hashes.
            </Alert>
          ) : (
            <Alert color="red" variant="light" icon={<IconCircleX size={18} />} title="Chain broken" role="alert">
              Entry {verify.data.first_bad_id ?? "unknown"} doesn't match its hash: it or an entry before it was changed or
              removed outside Sentinel. {verify.data.entries.toLocaleString()} entries checked.
            </Alert>
          )
        ) : (
          <Text size="sm" c="dimmed">
            Not checked in this session.
          </Text>
        )}
      </Panel>
      <Panel padded={false} title="Audit log">
        <div className={classes.filters} role="search" aria-label="Filter audit log">
          <TextInput size="xs" label="Action starts with" placeholder="e.g. scan. or auth.login" value={actionInput} onChange={(e) => setActionInput(e.currentTarget.value)} w={220} />
          <TextInput size="xs" label="Actor" placeholder="e.g. user:ryan or device:1" value={actorInput} onChange={(e) => setActorInput(e.currentTarget.value)} w={220} />
        </div>
        {audit.isPending ? <Loading /> : null}
        {audit.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorState error={audit.error} onRetry={() => void audit.refetch()} />
          </div>
        ) : null}
        {audit.data && audit.data.items.length === 0 ? <Empty title="No entries match" /> : null}
        {audit.data && audit.data.items.length > 0 ? (
          <>
            <div style={{ overflowX: "auto" }}>
              <Table miw={860}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>When</Table.Th>
                    <Table.Th>Actor</Table.Th>
                    <Table.Th>Action</Table.Th>
                    <Table.Th>Target</Table.Th>
                    <Table.Th>Details</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {audit.data.items.map((a) => (
                    <AuditRow key={a.id} a={a} open={expanded === a.id} onToggle={() => setExpanded(expanded === a.id ? null : a.id)} />
                  ))}
                </Table.Tbody>
              </Table>
            </div>
            <Pager total={audit.data.total} limit={page.limit} offset={page.offset} onChange={setPage} pageSizes={[50, 100, 200]} />
          </>
        ) : null}
      </Panel>
    </Stack>
  );
}

function AuditRow({ a, open, onToggle }: { a: AuditEntry; open: boolean; onToggle: () => void }) {
  const hasDetail = Object.keys(a.detail).length > 0;
  return (
    <>
      <Table.Tr>
        <Table.Td>
          <Time value={a.ts} />
        </Table.Td>
        <Table.Td className="sn-mono">{a.actor}</Table.Td>
        <Table.Td className="sn-mono">{a.action}</Table.Td>
        <Table.Td>{a.target_type ? `${humanize(a.target_type)} ${a.target_id ?? ""}` : <span className="sn-dim">–</span>}</Table.Td>
        <Table.Td>
          {hasDetail ? (
            <Button size="compact-xs" variant="subtle" onClick={onToggle} aria-expanded={open}>
              {open ? "Hide" : "Show"}
            </Button>
          ) : (
            <span className="sn-dim">–</span>
          )}
        </Table.Td>
      </Table.Tr>
      {open ? (
        <Table.Tr>
          <Table.Td colSpan={5}>
            <JsonView value={a.detail} maxHeight={220} />
            <Text size="xs" c="dimmed" mt={4} className="sn-mono">
              entry {a.id}, hash {a.hash}
            </Text>
          </Table.Td>
        </Table.Tr>
      ) : null}
    </>
  );
}

// ------------------------------------------------------------------------------------------ notifications

const DEFAULT_NOTIFY: NotificationSettings = {
  min_severity: "high",
  quiet_hours_enabled: false,
  quiet_start: "22:00",
  quiet_end: "07:00",
  timezone: "America/New_York",
  email_enabled: false,
  email_to: "",
  smtp_host: "",
  smtp_port: 587,
  smtp_username: "",
  smtp_from: "",
  smtp_starttls: true,
};

function NotificationsTab() {
  const settings = useAppSettings();
  const save = useSaveSetting("notifications");
  const test = useTestEmail();
  const [form, setForm] = useState<NotificationSettings>(DEFAULT_NOTIFY);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (settings.data && !loaded) {
      setForm({ ...DEFAULT_NOTIFY, ...settings.data.notifications });
      setLoaded(true);
    }
  }, [settings.data, loaded]);

  if (settings.isPending) return <Loading />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;

  const set = <K extends keyof NotificationSettings>(k: K, v: NotificationSettings[K]) => setForm((f) => ({ ...f, [k]: v }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate({ ...form }, { onSuccess: () => notifications.show({ message: "Notification settings saved" }) });
  };

  return (
    <form onSubmit={submit}>
      <Stack gap="md" maw={760}>
        <Panel title="In-app notifications" description="The bell in the top bar lists new findings, alerts, failed scans and missed schedules.">
          <Stack gap="sm">
            <Select
              label="Notify me about findings and alerts at or above"
              data={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))}
              value={form.min_severity}
              onChange={(v) => v && set("min_severity", v)}
              w={260}
            />
            <Switch
              label="Quiet hours"
              description="Emails are held during quiet hours and sent in the first digest after. In-app notifications still appear."
              checked={form.quiet_hours_enabled}
              onChange={(e) => set("quiet_hours_enabled", e.currentTarget.checked)}
            />
            {form.quiet_hours_enabled ? (
              <Group gap="sm" align="flex-end">
                <TextInput label="From" type="time" value={form.quiet_start} onChange={(e) => set("quiet_start", e.currentTarget.value)} w={130} />
                <TextInput label="Until" type="time" value={form.quiet_end} onChange={(e) => set("quiet_end", e.currentTarget.value)} w={130} />
                <TextInput label="Time zone" value={form.timezone} onChange={(e) => set("timezone", e.currentTarget.value)} w={220} description="IANA name, e.g. America/New_York" />
              </Group>
            ) : null}
          </Stack>
        </Panel>
        <Panel
          title="Email digest"
          description="Optional. Sentinel sends one digest per background run through your own mail server. The SMTP password is stored as a secret on the Integrations page."
        >
          <Stack gap="sm">
            <Switch label="Send email notifications" checked={form.email_enabled} onChange={(e) => set("email_enabled", e.currentTarget.checked)} />
            <TextInput label="Send to" description="One or more addresses, separated by commas" value={form.email_to} onChange={(e) => set("email_to", e.currentTarget.value)} />
            <Group grow gap="sm">
              <TextInput label="SMTP server" placeholder="smtp.example.com" value={form.smtp_host} onChange={(e) => set("smtp_host", e.currentTarget.value)} />
              <NumberInput label="Port" min={1} max={65535} value={form.smtp_port} onChange={(v) => set("smtp_port", typeof v === "number" ? v : 587)} maw={120} />
            </Group>
            <Group grow gap="sm">
              <TextInput label="SMTP username" value={form.smtp_username} onChange={(e) => set("smtp_username", e.currentTarget.value)} autoComplete="off" />
              <TextInput label="From address" value={form.smtp_from} onChange={(e) => set("smtp_from", e.currentTarget.value)} />
            </Group>
            <Switch label="Use STARTTLS" checked={form.smtp_starttls} onChange={(e) => set("smtp_starttls", e.currentTarget.checked)} />
            <Text size="xs" c="dimmed">
              SMTP password:{" "}
              <Anchor component={Link} to="/integrations" size="xs">
                set it on the Integrations page
              </Anchor>{" "}
              (stored as <span className="sn-mono">smtp_password</span>).
            </Text>
            <Group gap="sm">
              <Button
                variant="default"
                leftSection={<IconMail size={16} />}
                loading={test.isPending}
                onClick={() => test.mutate()}
              >
                Send test email
              </Button>
              <Text size="xs" c="dimmed">
                Uses the saved settings. Save first if you changed them.
              </Text>
            </Group>
            {test.data ? (
              <Alert color={test.data.sent ? "green" : "red"} variant="light" icon={test.data.sent ? <IconCircleCheck size={18} /> : <IconCircleX size={18} />} role="status">
                {test.data.detail}
              </Alert>
            ) : null}
            {test.isError ? <ErrorState error={test.error} /> : null}
          </Stack>
        </Panel>
        {save.isError ? (
          <Alert color="red" variant="light" icon={<IconAlertCircle size={18} />} role="alert">
            {errorMessage(save.error)}
          </Alert>
        ) : null}
        <Group>
          <Button type="submit" loading={save.isPending}>
            Save notification settings
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

// ------------------------------------------------------------------------------------------ retention

function RetentionTab() {
  const settings = useAppSettings();
  const save = useSaveSetting("retention");
  const [form, setForm] = useState<RetentionSettings>({ log_event_days: 90, metric_days: 90 });
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    if (settings.data && !loaded) {
      setForm({ log_event_days: 90, metric_days: 90, ...settings.data.retention });
      setLoaded(true);
    }
  }, [settings.data, loaded]);
  if (settings.isPending) return <Loading />;
  if (settings.isError) return <ErrorState error={settings.error} />;
  return (
    <Panel title="How long to keep data" description="Older log events and health readings are deleted automatically. Scans, findings and the audit log are kept.">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ ...form }, { onSuccess: () => notifications.show({ message: "Retention saved" }) });
        }}
      >
        <Stack gap="sm" maw={420}>
          <NumberInput label="Log events (days)" min={1} max={3650} value={form.log_event_days} onChange={(v) => setForm((f) => ({ ...f, log_event_days: typeof v === "number" ? v : f.log_event_days }))} />
          <NumberInput label="Health readings (days)" min={1} max={3650} value={form.metric_days} onChange={(v) => setForm((f) => ({ ...f, metric_days: typeof v === "number" ? v : f.metric_days }))} />
          {save.isError ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(save.error)}
            </Text>
          ) : null}
          <Group>
            <Button type="submit" loading={save.isPending}>
              Save retention
            </Button>
          </Group>
        </Stack>
      </form>
    </Panel>
  );
}

// ------------------------------------------------------------------------------------------ account

function AccountTab() {
  const { state } = useAuth();
  const change = useChangePassword();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const issues = passwordIssues(next, state.username ?? "");
  const ready = current.length > 0 && next.length > 0 && issues.length === 0 && next === confirm;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    change.mutate(
      { current_password: current, new_password: next },
      {
        onSuccess: () => {
          setCurrent("");
          setNext("");
          setConfirm("");
          notifications.show({ title: "Password changed", message: "Other signed-in sessions were signed out." });
        },
      },
    );
  };
  return (
    <Panel title="Change password" description={`Signed in as ${state.username ?? "unknown"}. Changing the password signs out every other session.`}>
      <form onSubmit={submit}>
        <Stack gap="sm" maw={420}>
          <PasswordInput label="Current password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.currentTarget.value)} required />
          <PasswordInput
            label="New password"
            description="At least 12 characters."
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.currentTarget.value)}
            error={next && issues.length ? issues.join(" ") : undefined}
            required
          />
          <PasswordInput
            label="Confirm new password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.currentTarget.value)}
            error={confirm && confirm !== next ? "The passwords don't match." : undefined}
            required
          />
          {change.isError ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(change.error)}
            </Text>
          ) : null}
          <Group>
            <Tooltip label="Fill in all three fields" disabled={ready}>
              <Button type="submit" loading={change.isPending} disabled={!ready}>
                Change password
              </Button>
            </Tooltip>
          </Group>
        </Stack>
      </form>
    </Panel>
  );
}
