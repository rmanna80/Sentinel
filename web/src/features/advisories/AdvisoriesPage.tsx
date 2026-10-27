import { Button, Drawer, Group, Select, Stack, Switch, Text, TextInput } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconBookmark, IconCircleCheck, IconSearch, IconTrash } from "@tabler/icons-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { errorMessage, isApiError } from "../../api/client";
import type { AdvisoriesQuery, AdvisoryOut } from "../../api/types";
import { ExternalLink } from "../../components/ExternalLink";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { SeverityBadge } from "../../components/Severity";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { AdvisoryCard } from "./AdvisoryCard";
import classes from "./Advisories.module.css";
import { useAdvisories, useAdvisory, useAdvisorySummary, useRefreshFeed, useUpdateAdvisory } from "./api";
import { FeedSummary } from "./FeedSummary";
import { matchChips } from "./matchDetail";

const STATUS_FILTERS = [
  { value: "open", label: "Open (hides dismissed)" },
  { value: "all", label: "All" },
  { value: "pinned", label: "Pinned" },
  { value: "dismissed", label: "Dismissed" },
];

function asDate(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function AdvisoriesPage() {
  const [params, setParams] = useSearchParams();
  const summary = useAdvisorySummary();
  const refresh = useRefreshFeed();
  const [openId, setOpenId] = useState<number | null>(null);

  const [search, setSearch] = useState("");
  const [debounced] = useDebouncedValue(search, 300);

  const statusFilter = params.get("status") ?? "open";
  const matchedOnly = params.get("matched") === "1";
  const limit = Number(params.get("limit") ?? 50);
  const offset = Number(params.get("offset") ?? 0);

  const setOne = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "limit" && k !== "offset") next.delete("offset");
    setParams(next, { replace: true });
  };

  // "open" is the server default (dismissed hidden), so it is sent as no status param.
  const query: AdvisoriesQuery = {
    status: statusFilter === "open" ? undefined : statusFilter,
    matched: matchedOnly ? true : undefined,
    q: debounced.trim() || undefined,
    limit,
    offset,
  };
  const advisories = useAdvisories(query);

  const refreshNow = () =>
    refresh.mutate(undefined, {
      onSuccess: (s) =>
        notifications.show({ message: s.last_synced_at ? "Feed refreshed" : "Refresh requested" }),
      onError: (err) => {
        if (isApiError(err, 409)) notifications.show({ color: "red", message: errorMessage(err) });
      },
    });

  return (
    <>
      <PageHeader
        title="Advisories"
        description="Security news matched to the software, KEV entries and findings on your devices. An advisory is background reading: it never changes a check, a finding or a device on its own."
      />

      <Stack gap="md">
        {summary.isPending ? (
          <Loading label="Loading the feed" />
        ) : summary.isError ? (
          <ErrorState error={summary.error} onRetry={() => void summary.refetch()} title="Feed status unavailable" />
        ) : (
          <FeedSummary
            status={summary.data}
            onRefresh={refreshNow}
            refreshing={refresh.isPending}
            refreshError={refresh.isError ? errorMessage(refresh.error) : null}
          />
        )}

        <Panel padded={false}>
          <div className={classes.filters} role="search" aria-label="Filter advisories">
            <TextInput
              size="xs"
              label="Search"
              placeholder="Title, summary, CVE or tag"
              leftSection={<IconSearch size={14} />}
              value={search}
              onChange={(e) => {
                setSearch(e.currentTarget.value);
                if (offset) setOne("offset", null);
              }}
              w={260}
            />
            <Select
              size="xs"
              label="Status"
              w={200}
              data={STATUS_FILTERS}
              value={statusFilter}
              onChange={(v) => setOne("status", v === "open" ? null : v)}
            />
            <Switch
              size="sm"
              label="Matched to me only"
              checked={matchedOnly}
              onChange={(e) => setOne("matched", e.currentTarget.checked ? "1" : null)}
              pb={6}
            />
          </div>

          {advisories.isPending ? <Loading label="Loading advisories" /> : null}
          {advisories.isError ? (
            <div style={{ padding: 16 }}>
              <ErrorState error={advisories.error} onRetry={() => void advisories.refetch()} />
            </div>
          ) : null}
          {advisories.data && advisories.data.items.length === 0 ? (
            <Empty title="No advisories match these filters">
              {matchedOnly
                ? "Nothing matched to your inventory in this view. Turn off “Matched to me only” to see everything."
                : "Nothing to show yet. New security news appears here after the feed syncs."}
            </Empty>
          ) : null}
          {advisories.data && advisories.data.items.length > 0 ? (
            <>
              <ul className={classes.list}>
                {advisories.data.items.map((a) => (
                  <li key={a.id}>
                    <AdvisoryCard advisory={a} onOpen={() => setOpenId(a.id)} />
                  </li>
                ))}
              </ul>
              <Pager
                total={advisories.data.total}
                limit={limit}
                offset={offset}
                pageSizes={[25, 50, 100]}
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
      </Stack>

      <AdvisoryDrawer id={openId} onClose={() => setOpenId(null)} />
    </>
  );
}

function AdvisoryDrawer({ id, onClose }: { id: number | null; onClose: () => void }) {
  const detail = useAdvisory(id);
  const update = useUpdateAdvisory();
  const a = detail.data;

  const act = (status: AdvisoryOut["status"], message: string) => {
    if (id === null) return;
    update.mutate(
      { id, body: { status } },
      { onSuccess: () => notifications.show({ message }) },
    );
  };

  return (
    <Drawer opened={id !== null} onClose={onClose} position="right" size="lg" title="Advisory" padding="lg">
      {detail.isPending ? <Loading label="Loading advisory" /> : null}
      {detail.isError ? <ErrorState error={detail.error} onRetry={() => void detail.refetch()} /> : null}
      {a ? (
        <Stack gap="md">
          <div>
            <Group gap={8} mb={6}>
              <SeverityBadge severity={a.severity_hint} size="md" />
              {a.matched ? <Tag tone="accent">Matched to you</Tag> : null}
              <Tag tone={a.status === "pinned" ? "warn" : a.status === "dismissed" ? "neutral" : "accent"}>{a.status}</Tag>
            </Group>
            <Text fw={650} size="md">
              <ExternalLink url={a.url}>{a.title}</ExternalLink>
            </Text>
            <Text size="xs" c="dimmed" mt={4}>
              {a.source}
              {a.author ? ` · by ${a.author}` : ""}
              {a.score !== null ? ` · score ${a.score}` : ""} · published{" "}
              <Time value={asDate(a.published_at)} mode="relative" empty="undated" />
            </Text>
          </div>

          {a.summary ? (
            <div className={classes.drawerSection}>
              <Text fw={650} size="sm" mb={4}>
                Summary
              </Text>
              <Text className={classes.coverage}>{a.summary}</Text>
            </div>
          ) : null}

          <MatchSection advisory={a} />

          <div className={classes.drawerSection}>
            <Text fw={650} size="sm" mb={4}>
              Suggested coverage
            </Text>
            <Text size="xs" c="dimmed" mb={6}>
              A human-reviewed note on how Sentinel's checks relate to this news. It is written guidance for you, not an
              automated change: nothing here alters a check, a finding or a device.
            </Text>
            <Text className={classes.coverage}>
              {a.suggested_coverage || "No coverage note has been written for this advisory."}
            </Text>
          </div>

          {a.url ? (
            <Text size="xs" c="dimmed">
              <ExternalLink url={a.url}>Read the original</ExternalLink>
            </Text>
          ) : null}

          {update.isError ? (
            <Text size="sm" c="red" role="alert">
              {errorMessage(update.error)}
            </Text>
          ) : null}

          <Group gap="sm">
            <Button
              variant="default"
              leftSection={<IconBookmark size={16} />}
              disabled={a.status === "pinned" || update.isPending}
              onClick={() => act("pinned", "Advisory pinned")}
            >
              Pin
            </Button>
            <Button
              variant="default"
              leftSection={<IconCircleCheck size={16} />}
              disabled={a.status === "read" || update.isPending}
              onClick={() => act("read", "Marked read")}
            >
              Mark read
            </Button>
            <Button
              variant="subtle"
              color="red"
              leftSection={<IconTrash size={16} />}
              disabled={a.status === "dismissed" || update.isPending}
              onClick={() => act("dismissed", "Advisory dismissed")}
            >
              Dismiss
            </Button>
          </Group>
        </Stack>
      ) : null}
    </Drawer>
  );
}

function MatchSection({ advisory }: { advisory: AdvisoryOut }) {
  const chips = matchChips(advisory.match_detail);
  const hasChips = chips.software.length || chips.kevCves.length || chips.findingCves.length;
  if (!advisory.tags.length && !advisory.cve_ids.length && !hasChips) return null;
  return (
    <div className={classes.drawerSection}>
      <Text fw={650} size="sm" mb={6}>
        Why this is here
      </Text>
      <div className={classes.chips} style={{ marginTop: 0 }}>
        {advisory.cve_ids.map((c) => (
          <span key={`cve-${c}`} className={classes.cve}>
            {c}
          </span>
        ))}
        {advisory.tags.map((t) => (
          <Tag key={`tag-${t}`}>{t}</Tag>
        ))}
        {chips.software.map((s) => (
          <Tag key={`sw-${s}`} tone="accent" title="In your software inventory">
            {s}
          </Tag>
        ))}
        {chips.kevCves.map((c) => (
          <Tag key={`kev-${c}`} tone="danger" title="On CISA KEV">
            KEV {c}
          </Tag>
        ))}
        {chips.findingCves.map((c) => (
          <Tag key={`fc-${c}`} tone="warn" title="Matches an open finding">
            Finding {c}
          </Tag>
        ))}
      </div>
    </div>
  );
}
