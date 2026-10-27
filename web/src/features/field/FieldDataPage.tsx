import { Button, Group, Modal, Select, Stack, Table, Tabs, Text } from "@mantine/core";
import { IconTrash } from "@tabler/icons-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { CaptureOut, CapturesQuery } from "../../api/types";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { Pager } from "../../components/Pager";
import { RowLink } from "../../components/RowLink";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { formatBytes, humanize } from "../../lib/format";
import { useCaptures, useDeleteCapture, useFieldSummary } from "./api";
import classes from "./Field.module.css";
import { FieldSummaryTiles } from "./FieldSummaryTiles";
import { KnownNetworksEditor } from "./KnownNetworksEditor";
import { UploadSurvey } from "./UploadSurvey";

const TABS = ["captures", "upload", "known"] as const;

const KIND_FILTERS = [
  { value: "", label: "All kinds" },
  { value: "wifi_survey", label: "Wi-Fi survey" },
  { value: "rf_survey", label: "RF survey" },
  { value: "host_report", label: "Host report" },
  { value: "generic", label: "Generic" },
];

export function FieldDataPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab = (TABS as readonly string[]).includes(raw ?? "") ? (raw as string) : "captures";
  const summary = useFieldSummary();

  return (
    <>
      <PageHeader
        title="Field Data"
        description="Passive surveys you captured in the field. Sentinel never scans or transmits here; it only correlates what you upload against your own known networks."
      />

      <Stack gap="md">
        {summary.isPending ? (
          <Loading label="Loading field summary" />
        ) : summary.isError ? (
          <ErrorState error={summary.error} onRetry={() => void summary.refetch()} title="Field summary unavailable" />
        ) : (
          <FieldSummaryTiles summary={summary.data} />
        )}

        <Tabs
          value={tab}
          onChange={(v) => setParams(v && v !== "captures" ? { tab: v } : {}, { replace: true })}
          keepMounted={false}
        >
          <Tabs.List mb="md">
            <Tabs.Tab value="captures">Captures</Tabs.Tab>
            <Tabs.Tab value="upload">Upload survey</Tabs.Tab>
            <Tabs.Tab value="known">Known networks</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="captures">
            <CapturesTab />
          </Tabs.Panel>
          <Tabs.Panel value="upload">
            <UploadSurvey />
          </Tabs.Panel>
          <Tabs.Panel value="known">
            <KnownNetworksEditor />
          </Tabs.Panel>
        </Tabs>
      </Stack>
    </>
  );
}

function countOf(summary: Record<string, unknown>, key: string): number {
  return typeof summary[key] === "number" ? (summary[key] as number) : 0;
}

function CapturesTab() {
  const [kind, setKind] = useState("");
  const [page, setPage] = useState({ limit: 50, offset: 0 });
  const [removing, setRemoving] = useState<CaptureOut | null>(null);
  const del = useDeleteCapture();
  const query: CapturesQuery = { kind: kind || undefined, ...page };
  const captures = useCaptures(query);

  return (
    <Panel padded={false}>
      <Group p="md" pb="sm" gap="sm">
        <Select
          size="xs"
          label="Kind"
          w={180}
          data={KIND_FILTERS}
          value={kind}
          onChange={(v) => {
            setKind(v ?? "");
            setPage((p) => ({ ...p, offset: 0 }));
          }}
        />
      </Group>
      {captures.isPending ? <Loading label="Loading captures" /> : null}
      {captures.isError ? (
        <div style={{ padding: 16 }}>
          <ErrorState error={captures.error} onRetry={() => void captures.refetch()} />
        </div>
      ) : null}
      {captures.data && captures.data.items.length === 0 ? (
        <Empty title="No captures yet">Upload a survey on the Upload tab to classify what you captured in the field.</Empty>
      ) : null}
      {captures.data && captures.data.items.length > 0 ? (
        <>
          <div className={classes.tableWrap}>
            <Table miw={900} stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Source</Table.Th>
                  <Table.Th>Kind</Table.Th>
                  <Table.Th>Records</Table.Th>
                  <Table.Th>Findings</Table.Th>
                  <Table.Th>Uploaded</Table.Th>
                  <Table.Th>Size</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {captures.data.items.map((c) => {
                  const rogue = countOf(c.summary, "rogue_suspects");
                  const weak = countOf(c.summary, "weak_own");
                  return (
                    <Table.Tr key={c.id}>
                      <Table.Td>
                        <RowLink to={`/field/${c.id}`}>{c.source_label || `Capture ${c.id}`}</RowLink>
                        {c.notes ? (
                          <Text size="xs" c="dimmed">
                            {c.notes}
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td>
                        <Tag>{humanize(c.kind)}</Tag>
                      </Table.Td>
                      <Table.Td className="sn-num">{c.record_count}</Table.Td>
                      <Table.Td>
                        <Group gap={6}>
                          {rogue > 0 ? <Tag tone="danger">{rogue} rogue</Tag> : null}
                          {weak > 0 ? <Tag tone="warn">{weak} weak</Tag> : null}
                          {rogue === 0 && weak === 0 ? <Text size="xs" c="dimmed">None flagged</Text> : null}
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Time value={c.uploaded_at} mode="relative" />
                      </Table.Td>
                      <Table.Td className="sn-num">{formatBytes(c.size_bytes)}</Table.Td>
                      <Table.Td>
                        <Button
                          size="compact-xs"
                          variant="subtle"
                          color="red"
                          leftSection={<IconTrash size={14} />}
                          onClick={() => setRemoving(c)}
                        >
                          Delete
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </div>
          <Pager total={captures.data.total} limit={page.limit} offset={page.offset} pageSizes={[25, 50, 100]} onChange={setPage} />
        </>
      ) : null}

      <Modal opened={removing !== null} onClose={() => setRemoving(null)} title="Delete this capture?" size="sm">
        <Text size="sm">
          {removing ? removing.source_label || `Capture ${removing.id}` : ""} and its observations will be permanently
          removed.
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
            onClick={() => removing && del.mutate(removing.id, { onSuccess: () => setRemoving(null) })}
          >
            Delete
          </Button>
        </Group>
      </Modal>
    </Panel>
  );
}
