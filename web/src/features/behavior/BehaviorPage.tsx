import { Button, Drawer, Group, Select, Stack, Text, TextInput } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconCircleCheck, IconCircleDashed, IconSearch, IconTrash } from "@tabler/icons-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { DetectionStatusUpdate } from "../../api/types";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { SeverityBadge } from "../../components/Severity";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { buildDetectionsQuery, useBehaviorSummary, useDetection, useDetections, useUpdateDetection } from "./api";
import classes from "./Behavior.module.css";
import { BehaviorSummaryTiles } from "./BehaviorSummaryTiles";
import { DetectionCard, StatusTag, TechniqueChips } from "./DetectionCard";
import { EventList } from "./EventList";
import { ProcessTree } from "./ProcessTree";

const STATUS_FILTERS = [
  { value: "open", label: "Open (new + acknowledged)" },
  { value: "new", label: "New" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "dismissed", label: "Dismissed" },
  { value: "all", label: "All" },
];

const SEVERITY_FILTERS = [
  { value: "", label: "Any severity" },
  ...SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] })),
];

export function BehaviorPage() {
  const [params, setParams] = useSearchParams();
  const summary = useBehaviorSummary();
  const [openId, setOpenId] = useState<number | null>(null);

  const [search, setSearch] = useState(params.get("q") ?? "");
  const [debounced] = useDebouncedValue(search, 300);

  const statusFilter = params.get("status") ?? "open";
  const severity = params.get("severity") ?? "";
  const host = params.get("host") ?? "";
  const limit = Number(params.get("limit") ?? 50);
  const offset = Number(params.get("offset") ?? 0);

  const setOne = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "limit" && k !== "offset") next.delete("offset");
    setParams(next, { replace: true });
  };

  const query = buildDetectionsQuery({
    status: statusFilter,
    severity: severity || undefined,
    host: host || undefined,
    q: debounced,
    limit,
    offset,
  });
  const detections = useDetections(query);

  return (
    <>
      <PageHeader
        title="Behavior"
        description="Behavioural detections correlated from operating-system telemetry on your devices. Each detection is a conclusion with its own evidence — review it before acting. Nothing here is remediated automatically."
      />

      <Stack gap="md">
        {summary.isPending ? (
          <Loading label="Loading the summary" />
        ) : summary.isError ? (
          <ErrorState error={summary.error} onRetry={() => void summary.refetch()} title="Summary unavailable" />
        ) : (
          <BehaviorSummaryTiles summary={summary.data} />
        )}

        <Panel padded={false}>
          <div className={classes.filters} role="search" aria-label="Filter detections">
            <TextInput
              size="xs"
              label="Search"
              placeholder="Title or summary"
              leftSection={<IconSearch size={14} />}
              value={search}
              onChange={(e) => {
                setSearch(e.currentTarget.value);
                setOne("q", e.currentTarget.value || null);
              }}
              w={240}
            />
            <Select
              size="xs"
              label="Status"
              w={210}
              data={STATUS_FILTERS}
              value={statusFilter}
              onChange={(v) => setOne("status", v === "open" ? null : v)}
            />
            <Select
              size="xs"
              label="Severity"
              w={150}
              data={SEVERITY_FILTERS}
              value={severity}
              onChange={(v) => setOne("severity", v || null)}
            />
            <TextInput
              size="xs"
              label="Host"
              placeholder="Any host"
              value={host}
              onChange={(e) => setOne("host", e.currentTarget.value || null)}
              w={200}
            />
          </div>

          {detections.isPending ? <Loading label="Loading detections" /> : null}
          {detections.isError ? (
            <div style={{ padding: 16 }}>
              <ErrorState error={detections.error} onRetry={() => void detections.refetch()} />
            </div>
          ) : null}
          {detections.data && detections.data.items.length === 0 ? (
            <Empty title="No detections match these filters">
              Nothing to show in this view. Behavioural detections appear here as your devices report them.
            </Empty>
          ) : null}
          {detections.data && detections.data.items.length > 0 ? (
            <>
              <ul className={classes.list}>
                {detections.data.items.map((d) => (
                  <li key={d.id}>
                    <DetectionCard detection={d} onOpen={() => setOpenId(d.id)} />
                  </li>
                ))}
              </ul>
              <Pager
                total={detections.data.total}
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

      <DetectionDrawer id={openId} onClose={() => setOpenId(null)} />
    </>
  );
}

export function DetectionDrawer({ id, onClose }: { id: number | null; onClose: () => void }) {
  const detail = useDetection(id);
  const update = useUpdateDetection();
  const d = detail.data;

  const act = (status: DetectionStatusUpdate["status"], message: string) => {
    if (id === null) return;
    update.mutate({ id, body: { status } }, { onSuccess: () => notifications.show({ message }) });
  };

  return (
    <Drawer opened={id !== null} onClose={onClose} position="right" size="lg" title="Detection" padding="lg">
      {detail.isPending ? <Loading label="Loading detection" /> : null}
      {detail.isError ? <ErrorState error={detail.error} onRetry={() => void detail.refetch()} /> : null}
      {d ? (
        <Stack gap="md">
          <div>
            <Group gap={8} mb={6}>
              <SeverityBadge severity={d.severity} size="md" />
              <StatusTag status={d.status} />
              {d.count > 1 ? <Tag tone="warn">{d.count}× seen</Tag> : null}
            </Group>
            <Text fw={650} size="md">
              {d.title}
            </Text>
            <Text size="xs" c="dimmed" mt={4}>
              <span className="sn-mono">{d.rule_id}</span> · {d.host} · last seen{" "}
              <Time value={d.last_ts} mode="relative" empty="undated" />
            </Text>
          </div>

          {d.technique_ids.length ? (
            <div className={classes.chips} style={{ marginTop: 0 }}>
              <TechniqueChips ids={d.technique_ids} names={d.technique_names} />
            </div>
          ) : null}

          {d.summary ? (
            <div className={classes.drawerSection}>
              <Text fw={650} size="sm" mb={4}>
                Summary
              </Text>
              <Text size="sm" style={{ lineHeight: 1.6 }}>
                {d.summary}
              </Text>
            </div>
          ) : null}

          {d.explanation ? (
            <div className={classes.drawerSection}>
              <Text fw={650} size="sm" mb={4}>
                Why this fired
              </Text>
              <div className={classes.explanation}>{d.explanation}</div>
            </div>
          ) : null}

          <div className={classes.drawerSection}>
            <Text fw={650} size="sm" mb={6}>
              Process tree
            </Text>
            <ProcessTree tree={d.process_tree} />
          </div>

          <div className={classes.drawerSection}>
            <Text fw={650} size="sm" mb={6}>
              Triggering events
            </Text>
            <EventList events={d.events} />
          </div>

          {update.isError ? (
            <Text size="sm" c="red" role="alert">
              {errorMessage(update.error)}
            </Text>
          ) : null}

          <Group gap="sm">
            <Button
              variant="default"
              leftSection={<IconCircleCheck size={16} />}
              disabled={d.status === "acknowledged" || update.isPending}
              onClick={() => act("acknowledged", "Detection acknowledged")}
            >
              Acknowledge
            </Button>
            <Button
              variant="subtle"
              color="red"
              leftSection={<IconTrash size={16} />}
              disabled={d.status === "dismissed" || update.isPending}
              onClick={() => act("dismissed", "Detection dismissed")}
            >
              Dismiss
            </Button>
            <Button
              variant="subtle"
              leftSection={<IconCircleDashed size={16} />}
              disabled={d.status === "new" || update.isPending}
              onClick={() => act("new", "Marked new")}
            >
              Mark new
            </Button>
          </Group>
        </Stack>
      ) : null}
    </Drawer>
  );
}
