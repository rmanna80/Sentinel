import { Alert, Button, Group, List, Loader, ScrollArea, Select, Stack, Tabs, Text, Textarea, TextInput, UnstyledButton } from "@mantine/core";
import { IconAlertCircle, IconPlus, IconSend, IconTrash } from "@tabler/icons-react";
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { AssistantStatus, MessageOut, ScanSummary } from "../../api/types";
import { CvssExplain } from "../../components/CvssExplain";
import { DemoBadge, isFixture } from "../../components/DemoData";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Tag } from "../../components/Status";
import { formatRelative, humanize } from "../../lib/format";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useScans } from "../scans/api";
import {
  useAssistantStatus,
  useConversation,
  useConversations,
  useCreateConversation,
  useDeleteConversation,
  useSendMessage,
  useSummarizeScan,
} from "./api";
import classes from "./Assistant.module.css";
import { CitedText, type CitationCheck } from "./CitedText";

export function AssistantPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "tools" ? "tools" : "chat";
  const status = useAssistantStatus();
  return (
    <>
      <PageHeader
        title="AI security assistant"
        description="Ask about your stored security data. A local model (Ollama on this computer) reads it through read-only tools and must cite what it uses. It can't change anything or run commands."
      />
      <Tabs value={tab} onChange={(v) => setParams(v === "tools" ? { tab: "tools" } : {}, { replace: true })} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="chat">Chat</Tabs.Tab>
          <Tabs.Tab value="tools">Offline explanations</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="chat">
          {status.isError ? <ErrorState error={status.error} /> : null}
          {status.data ? <StatusBanner s={status.data} /> : null}
          <Chat ready={!!status.data?.enabled && status.data.reachable === true} />
        </Tabs.Panel>
        <Tabs.Panel value="tools">
          <OfflineTools />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

function StatusBanner({ s }: { s: AssistantStatus }) {
  const ok = s.enabled && s.reachable === true && s.model_installed !== false;
  if (ok) {
    return (
      <Text size="xs" c="dimmed" mb="sm">
        Model <span className="sn-mono">{s.model}</span> at <span className="sn-mono">{s.url}</span>. Answers can be wrong;
        check the cited records.
      </Text>
    );
  }
  return (
    <Alert color="yellow" variant="light" icon={<IconAlertCircle size={18} />} mb="md" title="The chat isn't available right now">
      <Text size="sm">{s.detail ?? "Ollama isn't reachable."}</Text>
      <Text size="sm" mt={6}>
        {!s.enabled ? (
          <>
            Turn on Ollama on the{" "}
            <Link to="/integrations" className="sn-link">
              Integrations
            </Link>{" "}
            page.{" "}
          </>
        ) : null}
        Explanations of scans, findings and CVSS vectors still work without it: see{" "}
        <Link to="/assistant?tab=tools" className="sn-link">
          Offline explanations
        </Link>
        .
      </Text>
    </Alert>
  );
}

function Chat({ ready }: { ready: boolean }) {
  const conversations = useConversations();
  const create = useCreateConversation();
  const del = useDeleteConversation();
  const [active, setActive] = useState<number | null>(null);

  useEffect(() => {
    if (active === null && conversations.data?.length) setActive(conversations.data[0].id);
  }, [active, conversations.data]);

  return (
    <div className={classes.chatGrid}>
      <Panel
        title="Conversations"
        padded={false}
        actions={
          <Button size="compact-xs" variant="default" leftSection={<IconPlus size={13} />} loading={create.isPending} onClick={() => create.mutate(undefined, { onSuccess: (c) => setActive(c.id) })}>
            New
          </Button>
        }
      >
        {conversations.isPending ? <Loading /> : null}
        {conversations.data && conversations.data.length === 0 ? (
          <Text size="sm" c="dimmed" p="md">
            No conversations yet.
          </Text>
        ) : null}
        <ul className={classes.convList}>
          {conversations.data?.map((c) => (
            <li key={c.id}>
              <UnstyledButton className={classes.conv} data-active={c.id === active || undefined} onClick={() => setActive(c.id)} aria-current={c.id === active ? "true" : undefined}>
                <span className={classes.convTitle}>{c.title}</span>
                <span className={classes.convMeta}>
                  {c.message_count} messages, {formatRelative(c.updated_at)}
                </span>
              </UnstyledButton>
            </li>
          ))}
        </ul>
      </Panel>
      <Panel
        padded={false}
        title={active ? (conversations.data?.find((c) => c.id === active)?.title ?? "Conversation") : "Conversation"}
        actions={
          active ? (
            <Button
              size="compact-xs"
              variant="subtle"
              color="red"
              leftSection={<IconTrash size={13} />}
              loading={del.isPending}
              onClick={() => del.mutate(active, { onSuccess: () => setActive(null) })}
            >
              Delete
            </Button>
          ) : null
        }
      >
        {active === null ? (
          <Empty
            title="Start a conversation"
            action={
              <Button onClick={() => create.mutate(undefined, { onSuccess: (c) => setActive(c.id) })} disabled={!ready}>
                New conversation
              </Button>
            }
          >
            Try "Which open findings on my laptop matter most?" or "Summarize failed sign-ins this week."
          </Empty>
        ) : (
          <Thread id={active} ready={ready} />
        )}
      </Panel>
    </div>
  );
}

function Thread({ id, ready }: { id: number; ready: boolean }) {
  const conv = useConversation(id);
  const send = useSendMessage(id);
  const [draft, setDraft] = useState("");
  const [pendingText, setPendingText] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [conv.data?.messages.length, pendingText]);

  const submit = (e?: FormEvent) => {
    e?.preventDefault();
    const text = draft.trim();
    if (!text || send.isPending) return;
    setPendingText(text);
    setDraft("");
    send.mutate(text, {
      onSettled: () => setPendingText(null),
      onError: () => setDraft(text),
    });
  };
  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  };

  const visible = (conv.data?.messages ?? []).filter((m) => m.role === "user" || m.role === "assistant");
  return (
    <div className={classes.thread}>
      <ScrollArea.Autosize mah="60vh" className={classes.messages}>
        <div className={classes.messageList} aria-live="polite">
          {conv.isPending ? <Loading /> : null}
          {conv.isError ? <ErrorState error={conv.error} /> : null}
          {visible.length === 0 && !pendingText && conv.data ? (
            <Text size="sm" c="dimmed">
              Ask a question about your devices, findings, alerts or logs.
            </Text>
          ) : null}
          {visible.map((m) => (
            <MessageBubble key={m.id} m={m} />
          ))}
          {pendingText ? (
            <>
              <div className={classes.msg} data-role="user">
                <div className={classes.msgBody}>{pendingText}</div>
              </div>
              <Group gap="xs" c="dimmed">
                <Loader size="xs" />
                <Text size="sm">Reading your data and writing an answer. Local models can take a minute.</Text>
              </Group>
            </>
          ) : null}
          <div ref={endRef} />
        </div>
      </ScrollArea.Autosize>
      {send.isError ? (
        <Alert color="red" variant="light" mx="md" role="alert">
          {errorMessage(send.error)}
        </Alert>
      ) : null}
      <form onSubmit={submit} className={classes.composer}>
        <Textarea
          aria-label="Message"
          placeholder={ready ? "Ask about your security data (Enter to send, Shift+Enter for a new line)" : "The chat is unavailable"}
          autosize
          minRows={1}
          maxRows={6}
          maxLength={4000}
          value={draft}
          onChange={(e) => setDraft(e.currentTarget.value)}
          onKeyDown={onKey}
          disabled={!ready}
          style={{ flex: 1 }}
        />
        <Button type="submit" leftSection={<IconSend size={16} />} disabled={!ready || !draft.trim()} loading={send.isPending}>
          Send
        </Button>
      </form>
    </div>
  );
}

function MessageBubble({ m }: { m: MessageOut }) {
  const checks: CitationCheck[] = m.citations.map((c) => ({
    type: String(c.type ?? ""),
    id: String(c.id ?? ""),
    valid: c.valid === true,
  }));
  return (
    <div className={classes.msg} data-role={m.role}>
      <div className={classes.msgMeta}>
        {m.role === "user" ? "You" : `Assistant${m.model ? ` (${m.model})` : ""}`}, {formatRelative(m.created_at)}
      </div>
      <div className={classes.msgBody}>{m.role === "assistant" ? <CitedText text={m.content} checks={checks} /> : m.content}</div>
    </div>
  );
}

// ------------------------------------------------------------------------------------------ offline tools

function OfflineTools() {
  return (
    <div className={classes.toolsGrid}>
      <ScanSummaryTool />
      <CvssTool />
      <Panel title="Explain a finding" description="Every finding page has a plain-language explanation built from its evidence.">
        <Text size="sm">
          Open a finding from{" "}
          <Link to="/vulnerabilities" className="sn-link">
            Vulnerabilities
          </Link>{" "}
          and use <strong>Explain</strong>.
        </Text>
      </Panel>
    </div>
  );
}

function ScanSummaryTool() {
  const { deviceId } = useDeviceScope();
  const scans = useScans({ device_id: deviceId ?? undefined, limit: 30, offset: 0 });
  const summarize = useSummarizeScan();
  const [scanId, setScanId] = useState<string | null>(null);
  const finished = (scans.data?.items ?? []).filter((s) => s.status !== "queued" && s.status !== "running");
  return (
    <Panel title="Summarize a scan" description="What ran, what was skipped and why, and what changed since the previous scan. Built by fixed rules; no model involved.">
      <Group align="flex-end" gap="sm">
        <Select
          label="Scan"
          w={320}
          data={finished.map((s) => ({ value: String(s.id), label: `Scan ${s.id}: ${humanize(s.scan_type)}, ${humanize(s.status).toLowerCase()}` }))}
          value={scanId}
          onChange={setScanId}
          placeholder={scans.isPending ? "Loading scans" : "Choose a finished scan"}
          searchable
        />
        <Button disabled={!scanId} loading={summarize.isPending} onClick={() => scanId && summarize.mutate(Number(scanId))}>
          Summarize
        </Button>
      </Group>
      {summarize.isError ? <ErrorState error={summarize.error} /> : null}
      {summarize.data ? <SummaryView s={summarize.data} /> : null}
    </Panel>
  );
}

function SummaryView({ s }: { s: ScanSummary }) {
  return (
    <Stack gap="sm" mt="md">
      <Group gap="xs">
        <Tag>{humanize(s.scan_type)}</Tag>
        <Tag>{humanize(s.status)}</Tag>
        {isFixture(s.data_mode) ? <DemoBadge /> : null}
        <Text size="sm">
          {s.device_name}, score {s.score ?? (s.incomplete ? "Incomplete" : "not scored")}
        </Text>
      </Group>
      <div className={classes.summaryText}>
        <CitedText text={s.text} />
      </div>
      {s.limitations.length ? (
        <List size="xs" c="dimmed">
          {s.limitations.map((l) => (
            <List.Item key={l}>{l}</List.Item>
          ))}
        </List>
      ) : null}
    </Stack>
  );
}

function CvssTool() {
  const [input, setInput] = useState("");
  const [vector, setVector] = useState<string | null>(null);
  return (
    <Panel title="Read a CVSS vector" description="Paste a CVSS 3.x or 4.0 vector to see each metric in plain words.">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setVector(input.trim() || null);
        }}
      >
        <Group align="flex-end" gap="sm" mb="md">
          <TextInput label="Vector" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" value={input} onChange={(e) => setInput(e.currentTarget.value)} classNames={{ input: "sn-mono" }} style={{ flex: 1 }} maxLength={200} />
          <Button type="submit" disabled={input.trim().length < 3}>
            Explain
          </Button>
        </Group>
      </form>
      {vector ? <CvssExplain vector={vector} /> : null}
    </Panel>
  );
}
