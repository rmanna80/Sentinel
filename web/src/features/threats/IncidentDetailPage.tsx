import { Button, Group, Select, Stack, Table, Text, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { IncidentDetail } from "../../api/types";
import { Facts } from "../../components/Facts";
import { ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { RowLink } from "../../components/RowLink";
import { SeverityBadge } from "../../components/Severity";
import { StatusBadge } from "../../components/Status";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import { INCIDENT_STATUSES, useIncident, useUpdateIncident } from "./api";
import classes from "./Threats.module.css";

export function IncidentDetailPage() {
  const id = Number(useParams().incidentId);
  const q = useIncident(id);
  if (!Number.isInteger(id) || id <= 0) return <ErrorState error={new Error("That incident link isn't valid.")} />;
  if (q.isPending) return <Loading label="Loading incident" />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return <IncidentBody inc={q.data} />;
}

function IncidentBody({ inc }: { inc: IncidentDetail }) {
  const update = useUpdateIncident(inc.id);
  const [status, setStatus] = useState(inc.status);
  const [summary, setSummary] = useState(inc.summary ?? "");
  const dirty = status !== inc.status || summary !== (inc.summary ?? "");
  return (
    <>
      <PageHeader
        title={inc.title}
        docTitle={`Incident ${inc.id}`}
        meta={
          <>
            <SeverityBadge severity={inc.severity} size="md" />
            <StatusBadge kind="incident" value={inc.status} />
            <span>
              on{" "}
              <Link to={`/devices/${inc.device_id}`} className="sn-link">
                {inc.device_name ?? `Device ${inc.device_id}`}
              </Link>
            </span>
            <span>
              Opened <Time value={inc.opened_at} />
            </span>
          </>
        }
      />
      <div className={classes.grid}>
        <div className={classes.col}>
          <Panel title="Related alerts" description="Grouped because they share an account or address within two hours on this device." padded={false}>
            <div className={classes.tableWrap}>
              <Table miw={720} mt={8}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th w={110}>Severity</Table.Th>
                    <Table.Th>Alert</Table.Th>
                    <Table.Th>Events</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>First event</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {inc.alerts.map((a) => (
                    <Table.Tr key={a.id}>
                      <Table.Td>
                        <SeverityBadge severity={a.severity} />
                      </Table.Td>
                      <Table.Td>
                        <RowLink to={`/threats/alerts/${a.id}`}>{a.title}</RowLink>
                        {a.entity ? <div className="sn-mono sn-dim" style={{ fontSize: 12 }}>{a.entity}</div> : null}
                      </Table.Td>
                      <Table.Td className="sn-num">{a.event_count}</Table.Td>
                      <Table.Td>
                        <StatusBadge kind="alert" value={a.status} />
                      </Table.Td>
                      <Table.Td>
                        <Time value={a.first_event_at} mode="absolute" />
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </div>
          </Panel>
          <Panel title="Details">
            <Facts
              items={[
                ["Entities", inc.entities.length ? <span className="sn-mono">{inc.entities.join(", ")}</span> : "–"],
                ["Updated", <Time key="u" value={inc.updated_at} />],
                ["Closed", <Time key="c" value={inc.closed_at} empty="Still open" />],
              ]}
            />
          </Panel>
        </div>
        <div className={classes.col}>
          <Panel title="Status and summary">
            <Stack gap="sm">
              <Select
                label="Status"
                data={INCIDENT_STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
                value={status}
                onChange={(v) => v && setStatus(v)}
              />
              <Textarea
                label="Summary"
                description="Your write-up of what happened and what you did."
                autosize
                minRows={4}
                maxRows={14}
                maxLength={8000}
                value={summary}
                onChange={(e) => setSummary(e.currentTarget.value)}
              />
              {update.isError ? (
                <Text c="red" size="sm" role="alert">
                  {errorMessage(update.error)}
                </Text>
              ) : null}
              <Group justify="flex-end">
                <Button
                  disabled={!dirty}
                  loading={update.isPending}
                  onClick={() =>
                    update.mutate(
                      {
                        status: status !== inc.status ? (status as (typeof INCIDENT_STATUSES)[number]) : undefined,
                        summary: summary !== (inc.summary ?? "") ? summary : undefined,
                      },
                      { onSuccess: () => notifications.show({ message: "Incident updated" }) },
                    )
                  }
                >
                  Save
                </Button>
              </Group>
            </Stack>
          </Panel>
        </div>
      </div>
    </>
  );
}
