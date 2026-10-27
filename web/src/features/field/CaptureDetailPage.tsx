import { Stack, Table, Text } from "@mantine/core";
import { Link, useParams } from "react-router";
import type { CaptureDetail, FieldObservation } from "../../api/types";
import { Facts } from "../../components/Facts";
import { ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { SeverityBadge } from "../../components/Severity";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { formatBytes, humanize } from "../../lib/format";
import { useCapture } from "./api";
import { CLASSIFICATION, classificationOrder } from "./classification";
import classes from "./Field.module.css";

export function CaptureDetailPage() {
  const id = Number(useParams().captureId);
  const capture = useCapture(Number.isInteger(id) && id > 0 ? id : null);
  if (!Number.isInteger(id) || id <= 0) return <ErrorState error={new Error("That capture link isn't valid.")} />;
  if (capture.isPending) return <Loading label="Loading capture" />;
  if (capture.isError) return <ErrorState error={capture.error} onRetry={() => void capture.refetch()} />;
  return <CaptureBody c={capture.data} />;
}

function dataSummary(data: Record<string, unknown>): string {
  return Object.entries(data)
    .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
    .map(([k, v]) => `${k}: ${String(v)}`)
    .join("  ·  ");
}

function CaptureBody({ c }: { c: CaptureDetail }) {
  const observations: FieldObservation[] = [...c.observations].sort(
    (a, b) => classificationOrder(a.classification) - classificationOrder(b.classification) || a.label.localeCompare(b.label),
  );

  return (
    <>
      <PageHeader
        title={c.source_label || `Capture ${c.id}`}
        docTitle={`Capture ${c.id}`}
        meta={
          <>
            <Tag>{humanize(c.kind)}</Tag>
            <span>
              Uploaded <Time value={c.uploaded_at} mode="relative" />
            </span>
            <span>
              <Link to="/field" className="sn-link">
                All captures
              </Link>
            </span>
          </>
        }
      />

      <Stack gap="md">
      <Panel title="About this capture">
        <Facts
          columns={2}
          items={[
            ["Kind", humanize(c.kind)],
            ["Original format", c.original_format || "–"],
            ["Records", String(c.record_count)],
            ["Size", formatBytes(c.size_bytes)],
            ["SHA-256", <span key="h" className="sn-mono" style={{ overflowWrap: "anywhere" }}>{c.sha256}</span>],
            ["Notes", c.notes || "–"],
          ]}
        />
      </Panel>

      <Panel
        title="Observations"
        description="Each access point or host in the capture, classified against your known networks. Rogue suspects and your own weak networks are shown first."
        padded={false}
      >
        {observations.length === 0 ? (
          <Text size="sm" c="dimmed" p="md">
            No observations were recorded in this capture.
          </Text>
        ) : (
          <div className={classes.tableWrap}>
            <Table miw={880} stickyHeader>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Classification</Table.Th>
                  <Table.Th>Observed</Table.Th>
                  <Table.Th>Severity</Table.Th>
                  <Table.Th>Details</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {observations.map((o) => {
                  const cls = CLASSIFICATION[o.classification];
                  return (
                    <Table.Tr key={o.id} className={cls?.prominent ? classes.prominentRow : undefined}>
                      <Table.Td>
                        <Tag tone={cls?.tone ?? "neutral"}>{cls?.label ?? humanize(o.classification)}</Tag>
                      </Table.Td>
                      <Table.Td>
                        <div style={{ fontWeight: 550 }}>{o.label || o.key || humanize(o.kind)}</div>
                        {o.key && o.label ? (
                          <Text size="xs" c="dimmed" className="sn-mono">
                            {o.key}
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td>
                        <SeverityBadge severity={o.severity} variant="inline" />
                      </Table.Td>
                      <Table.Td>
                        {o.note ? <div style={{ fontSize: "var(--mantine-font-size-sm)" }}>{o.note}</div> : null}
                        {dataSummary(o.data) ? <div className={classes.obsData}>{dataSummary(o.data)}</div> : null}
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </div>
        )}
      </Panel>
      </Stack>
    </>
  );
}
