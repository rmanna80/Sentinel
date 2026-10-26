import { Alert, Button, Group, Radio, Stack, Text, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconInfoCircle } from "@tabler/icons-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { AlertDetail } from "../../api/types";
import { Facts } from "../../components/Facts";
import { JsonView } from "../../components/JsonView";
import { LogEventsTable } from "../../components/LogEventsTable";
import { ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { SeverityBadge } from "../../components/Severity";
import { StatusBadge } from "../../components/Status";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import { ALERT_STATUSES, useAlert, useUpdateAlert } from "./api";
import { KindTag } from "./ThreatsPage";
import classes from "./Threats.module.css";

export function AlertDetailPage() {
  const id = Number(useParams().alertId);
  const alert = useAlert(id);
  if (!Number.isInteger(id) || id <= 0) return <ErrorState error={new Error("That alert link isn't valid.")} />;
  if (alert.isPending) return <Loading label="Loading alert" />;
  if (alert.isError) return <ErrorState error={alert.error} onRetry={() => void alert.refetch()} />;
  return <AlertBody a={alert.data} />;
}

const STATUS_HELP: Record<string, string> = {
  new: "Not looked at yet.",
  acknowledged: "Seen; not yet investigated.",
  investigating: "Someone is looking into it.",
  resolved: "Handled. New matching events raise a new alert.",
  false_positive: "Not a real problem. Use the notes to say why.",
};

function AlertBody({ a }: { a: AlertDetail }) {
  const update = useUpdateAlert(a.id);
  const navigate = useNavigate();
  const [status, setStatus] = useState(a.status);
  const [notes, setNotes] = useState(a.notes ?? "");
  const dirty = status !== a.status || notes !== (a.notes ?? "");
  return (
    <>
      <PageHeader
        title={a.title}
        docTitle={`Alert ${a.id}`}
        meta={
          <>
            <SeverityBadge severity={a.severity} size="md" />
            <StatusBadge kind="alert" value={a.status} />
            <span>
              on{" "}
              <Link to={`/devices/${a.device_id}`} className="sn-link">
                {a.device_name ?? `Device ${a.device_id}`}
              </Link>
            </span>
            <span>
              Detected <Time value={a.detected_at} />
            </span>
          </>
        }
      />
      <div className={classes.grid}>
        <div className={classes.col}>
          <Panel title="What happened">
            <Text className={classes.prose}>{a.description}</Text>
            <Facts
              columns={2}
              items={[
                ["Entity", a.entity ? <span className="sn-mono">{a.entity}</span> : "–"],
                ["Events", a.event_count.toLocaleString()],
                ["First event", <Time key="f" value={a.first_event_at} />],
                ["Last event", <Time key="l" value={a.last_event_at} />],
                ["Rule", <span key="r" className="sn-mono">{a.rule_id}</span>],
                [
                  "Incident",
                  a.incident ? (
                    <Link key="i" to={`/threats/incidents/${a.incident.id}`} className="sn-link">
                      {a.incident.title}
                    </Link>
                  ) : (
                    "Not part of an incident"
                  ),
                ],
              ]}
            />
            <Group mt="sm">
              <KindTag kind={a.kind} confidence={a.confidence} />
            </Group>
          </Panel>
          <Panel title="How to investigate">
            <ol className={classes.steps}>
              {a.investigation_steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </Panel>
          <Panel title="What to do">
            <Text className={classes.prose}>{a.remediation || "No remediation advice for this rule."}</Text>
            <Text size="xs" c="dimmed" mt={6}>
              Sentinel never acts on a device. These are steps for you to carry out.
            </Text>
          </Panel>
          <Panel
            title="Matching log events"
            description={
              a.events_total > a.events.length
                ? `Showing the first ${a.events.length} of ${a.events_total.toLocaleString()} events.`
                : `${a.events_total} event${a.events_total === 1 ? "" : "s"}. Messages are shown as plain text: they can contain attacker-written content.`
            }
            padded={false}
          >
            <LogEventsTable events={a.events} onOpen={(eid) => navigate(`/logs?event=${eid}`)} />
          </Panel>
          <Panel title="Evidence summary" description="Counts and samples copied from stored log events. No AI-generated text.">
            <JsonView value={a.evidence} maxHeight={320} />
          </Panel>
        </div>
        <div className={classes.col}>
          <Panel title="Triage">
            <Stack gap="sm">
              <Radio.Group value={status} onChange={setStatus} label="Status">
                <Stack gap={8} mt={6}>
                  {ALERT_STATUSES.map((s) => (
                    <Radio key={s} value={s} label={humanize(s)} description={STATUS_HELP[s]} />
                  ))}
                </Stack>
              </Radio.Group>
              <Textarea label="Notes" autosize minRows={3} maxRows={10} maxLength={8000} value={notes} onChange={(e) => setNotes(e.currentTarget.value)} />
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
                        status: status !== a.status ? (status as (typeof ALERT_STATUSES)[number]) : undefined,
                        notes: notes !== (a.notes ?? "") ? notes : undefined,
                      },
                      { onSuccess: () => notifications.show({ message: "Alert updated" }) },
                    )
                  }
                >
                  Save
                </Button>
              </Group>
            </Stack>
          </Panel>
          <Alert variant="light" color="gray" icon={<IconInfoCircle size={16} />}>
            <Text size="xs">
              {a.kind === "verified"
                ? "Verified: the logs directly show this happened."
                : "Heuristic: this pattern is often harmless (a mistyped password, an admin tool). Check the events before acting."}
            </Text>
          </Alert>
        </div>
      </div>
    </>
  );
}
