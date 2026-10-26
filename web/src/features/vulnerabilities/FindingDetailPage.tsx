import {
  Accordion,
  Anchor,
  Button,
  Checkbox,
  Group,
  Modal,
  Stack,
  Text,
  TextInput,
  Textarea,
  Timeline,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCircleCheck, IconExternalLink, IconPlus, IconRefresh } from "@tabler/icons-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { Link, useParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { FindingDetail, Observation, Task } from "../../api/types";
import { CvssExplain } from "../../components/CvssExplain";
import { Facts } from "../../components/Facts";
import { JsonView } from "../../components/JsonView";
import { ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { KevBadge, SeverityBadge } from "../../components/Severity";
import { StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { formatBytes, formatDay, formatPercent, humanize } from "../../lib/format";
import { useExplainFinding } from "../assistant/api";
import { useCreateTask, useFinding, useUpdateFinding, useUpdateTask, useVerifyFinding, useVulnDetail } from "./api";
import classes from "./Findings.module.css";
import { StatusWorkflow } from "./StatusWorkflow";
import { CONFIDENCE_LABEL, FINDING_KIND, STATUS_LABEL } from "./workflow";

export function FindingDetailPage() {
  const id = Number(useParams().findingId);
  const finding = useFinding(id);
  if (!Number.isInteger(id) || id <= 0) return <ErrorState error={new Error("That finding link isn't valid.")} />;
  if (finding.isPending) return <Loading label="Loading finding" />;
  if (finding.isError) return <ErrorState error={finding.error} onRetry={() => void finding.refetch()} />;
  return <FindingBody f={finding.data} />;
}

function isUrl(s: string): boolean {
  return /^https?:\/\//i.test(s);
}

function FindingBody({ f }: { f: FindingDetail }) {
  const update = useUpdateFinding(f.id);
  const verify = useVerifyFinding(f.id);
  const kind = FINDING_KIND[f.finding_kind];
  const [confirmVerify, setConfirmVerify] = useState(false);

  return (
    <>
      <PageHeader
        title={f.title}
        docTitle={`Finding ${f.id}`}
        meta={
          <>
            <SeverityBadge severity={f.severity} size="md" />
            <StatusBadge kind="finding" value={f.status} />
            {f.kev ? <KevBadge /> : null}
            <span>
              on{" "}
              <Link to={`/devices/${f.device_id}`} className="sn-link">
                {f.device_name}
              </Link>
            </span>
            <span>
              First seen <Time value={f.first_seen_at} mode="relative" />, last seen{" "}
              <Time value={f.last_seen_at} mode="relative" />
            </span>
          </>
        }
        actions={
          f.status !== "resolved" ? (
            <Tooltip label="Re-runs the check that found this. Only a passing re-run resolves the finding.">
              <Button leftSection={<IconRefresh size={16} />} onClick={() => setConfirmVerify(true)} loading={verify.isPending}>
                Verify
              </Button>
            </Tooltip>
          ) : null
        }
      />

      <div className={classes.detailGrid}>
        <div className={classes.col}>
          <Panel title="What was found">
            <div className={classes.identity}>
              <Tooltip label={kind?.help ?? ""} disabled={!kind}>
                <span tabIndex={0}>
                  <Tag tone={f.finding_kind === "verified" ? "danger" : f.finding_kind === "heuristic" ? "warn" : "neutral"}>
                    {kind?.label ?? humanize(f.finding_kind)}
                  </Tag>
                </span>
              </Tooltip>
              <Tag>{CONFIDENCE_LABEL[f.confidence] ?? `${humanize(f.confidence)} confidence`}</Tag>
              <Tag>{humanize(f.category)}</Tag>
              <Tag>{f.source === "vuln_matcher" ? "Vulnerability matching" : "Device check"}</Tag>
            </div>
            {kind ? <Text className={classes.kindExplain}>{kind.help}</Text> : null}
            <Text fw={650} size="sm" mt="md" mb={4}>
              Impact
            </Text>
            <Text className={classes.prose}>{f.impact || "No impact statement was recorded."}</Text>
            <Text fw={650} size="sm" mt="md" mb={4}>
              How to fix it
            </Text>
            <Text className={classes.prose}>{f.remediation || "No remediation advice was recorded."}</Text>
            <Text size="xs" c="dimmed" mt={6}>
              Sentinel never changes your devices. These are steps for you to carry out.
            </Text>
            {f.references.length ? (
              <>
                <Text fw={650} size="sm" mt="md" mb={4}>
                  References
                </Text>
                <ul className={classes.refs}>
                  {f.references.map((r) => (
                    <li key={r}>
                      {isUrl(r) ? (
                        <Anchor href={r} target="_blank" rel="noopener noreferrer" size="sm">
                          {r} <IconExternalLink size={12} aria-label="(opens in a new tab)" />
                        </Anchor>
                      ) : (
                        r
                      )}
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </Panel>

          {f.cve_id || f.vuln_id || f.cvss_score !== null || f.epss !== null || f.kev ? <VulnPanel f={f} /> : null}

          <ExplanationPanel findingId={f.id} />

          <Panel
            title="Evidence"
            description="What the agent collected when it observed this. Secrets are redacted on the device before upload."
          >
            {f.observations.length === 0 ? (
              <Text size="sm" c="dimmed">
                No observations with evidence are stored for this finding.
              </Text>
            ) : (
              f.observations.map((o) => <ObservationBlock key={`${o.check_run_id}-${o.observed_at}`} o={o} />)
            )}
          </Panel>
        </div>

        <div className={classes.col}>
          <Panel title="Status">
            <StatusWorkflow
              status={f.status}
              allowedStatuses={f.allowed_statuses}
              pending={update.isPending}
              error={update.error}
              onSubmit={(body) =>
                update.mutate(body, {
                  onSuccess: () => notifications.show({ message: body.status ? `Status changed to ${STATUS_LABEL[body.status] ?? body.status}` : "Note added" }),
                })
              }
            />
          </Panel>
          <OwnerPanel f={f} />
          <TasksPanel f={f} />
          <Panel title="Details">
            <Facts
              items={[
                ["Rule", <span key="r" className="sn-mono">{f.rule_id}</span>],
                ["Check", <span key="c" className="sn-mono">{f.check_id}</span>],
                ["Subject", <span key="s" className="sn-mono">{f.subject_key}</span>],
                [
                  "First seen in",
                  f.first_seen_scan_id ? (
                    <Link key="fs" to={`/scans/${f.first_seen_scan_id}`} className="sn-link">
                      Scan {f.first_seen_scan_id}
                    </Link>
                  ) : (
                    "–"
                  ),
                ],
                [
                  "Last seen in",
                  f.last_seen_scan_id ? (
                    <Link key="ls" to={`/scans/${f.last_seen_scan_id}`} className="sn-link">
                      Scan {f.last_seen_scan_id}
                    </Link>
                  ) : (
                    "–"
                  ),
                ],
                ["Reopened", f.reopened_count ? `${f.reopened_count} time${f.reopened_count === 1 ? "" : "s"}` : "Never"],
                ["Verified resolved", <Time key="vr" value={f.verified_resolved_at} empty="No" />],
              ]}
            />
          </Panel>
          <Panel title="History">
            {f.events.length === 0 ? (
              <Text size="sm" c="dimmed">
                No changes yet.
              </Text>
            ) : (
              <Timeline bulletSize={14} lineWidth={2} active={-1}>
                {f.events.map((e) => (
                  <Timeline.Item
                    key={e.id}
                    title={
                      e.to_status ? (
                        <span>
                          {e.from_status
                            ? `${STATUS_LABEL[e.from_status] ?? e.from_status} to ${STATUS_LABEL[e.to_status] ?? e.to_status}`
                            : `Created as ${STATUS_LABEL[e.to_status] ?? e.to_status}`}
                        </span>
                      ) : (
                        <span>{Object.keys(e.changes).length ? `Changed ${Object.keys(e.changes).map(humanize).join(", ").toLowerCase()}` : "Note"}</span>
                      )
                    }
                  >
                    {e.note ? (
                      <Text size="sm" className={classes.prose}>
                        {e.note}
                      </Text>
                    ) : null}
                    <Text size="xs" c="dimmed" mt={2}>
                      {e.actor.replace(/^user:/, "")}, <Time value={e.created_at} mode="relative" />
                    </Text>
                  </Timeline.Item>
                ))}
              </Timeline>
            )}
          </Panel>
        </div>
      </div>

      <Modal opened={confirmVerify} onClose={() => setConfirmVerify(false)} title="Verify this finding" size="md">
        <Stack gap="sm">
          <Text size="sm">
            {f.source === "agent"
              ? "Sentinel queues a scan that re-runs only the check that found this. If the check passes, the finding is resolved. If it still sees the problem, the finding stays open."
              : "Sentinel queues an inventory scan. If the installed software no longer matches this vulnerability, the finding is resolved."}
          </Text>
          <Text size="sm" c="dimmed">
            The device's agent must be running to pick up the scan. If the check needs administrator rights, run
            scripts\elevated-scan.ps1 on the device.
          </Text>
          {verify.isError ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(verify.error)}
            </Text>
          ) : null}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setConfirmVerify(false)}>
              Cancel
            </Button>
            <Button
              loading={verify.isPending}
              onClick={() =>
                verify.mutate(undefined, {
                  onSuccess: (scan) => {
                    setConfirmVerify(false);
                    notifications.show({
                      title: "Verification queued",
                      message: (
                        <span>
                          <Link to={`/scans/${scan.id}`} className="sn-link">
                            Scan {scan.id}
                          </Link>{" "}
                          re-runs the check.
                        </span>
                      ),
                    });
                  },
                })
              }
            >
              Queue verification scan
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

function VulnFact({ label, value, note }: { label: string; value: ReactNode; note?: ReactNode }) {
  return (
    <div className={classes.vulnFact}>
      <div className={classes.vulnFactLabel}>{label}</div>
      <div className={classes.vulnFactValue}>{value}</div>
      {note ? <div className={classes.vulnFactNote}>{note}</div> : null}
    </div>
  );
}

function VulnPanel({ f }: { f: FindingDetail }) {
  const detail = useVulnDetail(f.vuln_id);
  const v = detail.data;
  const vector = v?.cvss_vector ?? f.cvss_vector;
  return (
    <Panel title="Vulnerability" description="From public vulnerability databases, matched against what's installed.">
      <div className={classes.vulnFacts}>
        <VulnFact label="CVE" value={f.cve_id ? <span className="sn-mono">{f.cve_id}</span> : <span className="sn-dim">None assigned</span>} note={f.vuln_id && f.vuln_id !== f.cve_id ? <span className="sn-mono">{f.vuln_id}</span> : undefined} />
        <VulnFact
          label="CVSS"
          value={f.cvss_score !== null ? f.cvss_score.toFixed(1) : <span className="sn-dim">Unavailable</span>}
          note={f.cvss_source ? `Source: ${f.cvss_source}` : undefined}
        />
        <VulnFact
          label="EPSS (exploit likelihood, 30 days)"
          value={f.epss !== null ? formatPercent(f.epss, 1) : <span className="sn-dim">Unavailable</span>}
          note={v?.epss_percentile != null ? `Higher than ${formatPercent(v.epss_percentile)} of scored CVEs` : undefined}
        />
        <VulnFact
          label="Known exploited (CISA KEV)"
          value={f.kev ? "Yes" : "No"}
          note={v?.kev_date_added ? `Added ${formatDay(v.kev_date_added)}${v.kev_ransomware ? `, ransomware use: ${v.kev_ransomware}` : ""}` : undefined}
        />
      </div>
      <Facts
        items={[
          ["Affected software", f.affected_software ?? "–"],
          ["Fixed in", f.fixed_version ?? <span className="sn-dim">No fixed version listed</span>],
          ...(v?.published ? ([["Published", formatDay(v.published)]] as [string, string][]) : []),
          ...(v?.nvd_status ? ([["NVD status", v.nvd_status]] as [string, string][]) : []),
        ]}
      />
      {v?.summary ? (
        <Text size="sm" mt="sm" className={classes.prose}>
          {v.summary}
        </Text>
      ) : null}
      {v?.enrichment_note ? (
        <Text size="xs" c="dimmed" mt="xs">
          {v.enrichment_note}
        </Text>
      ) : null}
      {detail.isError && f.vuln_id ? (
        <Text size="xs" c="dimmed" mt="xs">
          Vulnerability details aren't in the local cache yet ({errorMessage(detail.error)}).
        </Text>
      ) : null}
      {vector ? (
        <Accordion variant="contained" mt="md" chevronPosition="left">
          <Accordion.Item value="cvss">
            <Accordion.Control>
              CVSS vector <span className="sn-mono">{vector}</span>
            </Accordion.Control>
            <Accordion.Panel>
              <CvssExplain vector={vector} />
            </Accordion.Panel>
          </Accordion.Item>
        </Accordion>
      ) : null}
    </Panel>
  );
}

function ExplanationPanel({ findingId }: { findingId: number }) {
  const [open, setOpen] = useState(false);
  const q = useExplainFinding(open ? findingId : null);
  return (
    <Panel
      title="Plain-language explanation"
      description="Built from this finding's stored data and evidence by fixed rules. No AI model is involved."
      actions={
        !open ? (
          <Button size="xs" variant="default" onClick={() => setOpen(true)}>
            Explain
          </Button>
        ) : null
      }
    >
      {!open ? (
        <Text size="sm" c="dimmed">
          Get a short write-up of what this means, why it matters and what to do, with the evidence it's based on.
        </Text>
      ) : q.isPending ? (
        <Loading label="Building explanation" />
      ) : q.isError ? (
        <ErrorState error={q.error} />
      ) : (
        <Stack gap="sm">
          {Object.entries(q.data.sections).map(([k, v]) => (
            <div key={k}>
              <Text fw={650} size="sm">
                {humanize(k)}
              </Text>
              <Text size="sm" className={classes.prose}>
                {v}
              </Text>
            </div>
          ))}
        </Stack>
      )}
    </Panel>
  );
}

function ObservationBlock({ o }: { o: Observation }) {
  return (
    <div className={classes.obs}>
      <div className={classes.obsHead}>
        <strong>
          Observed <Time value={o.observed_at} />
        </strong>
        <Link to={`/scans/${o.scan_id}`} className="sn-link">
          Scan {o.scan_id}
        </Link>
      </div>
      {o.evidence.length === 0 ? (
        <Text size="sm" c="dimmed">
          No evidence stored with this observation.
        </Text>
      ) : (
        o.evidence.map((e) => (
          <div key={e.id} className={classes.evidence}>
            <div className={classes.evidenceMeta}>
              <Tag>{humanize(e.kind)}</Tag>
              <span>
                Source: <span className="sn-mono">{e.source}</span>
              </span>
              <span>{formatBytes(e.size_bytes)}</span>
              {e.redacted ? (
                <Tooltip label="Values that looked like secrets were replaced on the device before upload.">
                  <span tabIndex={0}>
                    <Tag tone="warn">Redacted</Tag>
                  </span>
                </Tooltip>
              ) : null}
              <span>
                Collected <Time value={e.collected_at} mode="relative" />
              </span>
            </div>
            <JsonView value={e.content} maxHeight={300} />
            <div className={classes.hash} title="SHA-256 of the evidence content as stored">
              sha256 {e.content_sha256}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function OwnerPanel({ f }: { f: FindingDetail }) {
  const update = useUpdateFinding(f.id);
  const [owner, setOwner] = useState(f.owner ?? "");
  const [target, setTarget] = useState(f.target_date ?? "");
  const dirty = owner !== (f.owner ?? "") || target !== (f.target_date ?? "");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    update.mutate(
      { owner: owner.trim() || null, target_date: target || null },
      { onSuccess: () => notifications.show({ message: "Owner and target date saved" }) },
    );
  };
  return (
    <Panel title="Ownership">
      <form onSubmit={submit}>
        <Stack gap="sm">
          <TextInput label="Owner" placeholder="Who is fixing this" value={owner} maxLength={128} onChange={(e) => setOwner(e.currentTarget.value)} />
          <TextInput
            label="Target date"
            type="date"
            value={target}
            onChange={(e) => setTarget(e.currentTarget.value)}
          />
          {update.isError ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(update.error)}
            </Text>
          ) : null}
          <Group justify="flex-end">
            <Button type="submit" variant="default" disabled={!dirty} loading={update.isPending}>
              Save
            </Button>
          </Group>
        </Stack>
      </form>
    </Panel>
  );
}

function TasksPanel({ f }: { f: FindingDetail }) {
  const create = useCreateTask(f.id);
  const updateTask = useUpdateTask(f.id);
  const [adding, setAdding] = useState(false);
  const [title, setTitle] = useState("");
  const [owner, setOwner] = useState("");
  const [due, setDue] = useState("");
  const [notes, setNotes] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    create.mutate(
      { title: title.trim(), owner: owner.trim() || null, due_date: due || null, notes: notes.trim() || null },
      {
        onSuccess: () => {
          setTitle("");
          setOwner("");
          setDue("");
          setNotes("");
          setAdding(false);
        },
      },
    );
  };

  return (
    <Panel
      title="Remediation tasks"
      actions={
        !adding ? (
          <Button size="xs" variant="default" leftSection={<IconPlus size={14} />} onClick={() => setAdding(true)}>
            Add task
          </Button>
        ) : null
      }
    >
      {f.tasks.length === 0 && !adding ? (
        <Text size="sm" c="dimmed">
          Break the fix into steps and track who does what.
        </Text>
      ) : null}
      <div>
        {f.tasks.map((t) => (
          <TaskRow
            key={t.id}
            t={t}
            pending={updateTask.isPending && updateTask.variables?.id === t.id}
            onToggle={(done) => updateTask.mutate({ id: t.id, body: { status: done ? "done" : "open" } })}
          />
        ))}
      </div>
      {updateTask.isError ? (
        <Text c="red" size="sm" role="alert">
          {errorMessage(updateTask.error)}
        </Text>
      ) : null}
      {adding ? (
        <form onSubmit={submit} style={{ marginTop: f.tasks.length ? 12 : 0 }}>
          <Stack gap="xs">
            <TextInput label="Task" value={title} onChange={(e) => setTitle(e.currentTarget.value)} required maxLength={300} data-autofocus autoFocus />
            <Group grow gap="xs">
              <TextInput label="Owner" value={owner} onChange={(e) => setOwner(e.currentTarget.value)} maxLength={128} />
              <TextInput label="Due" type="date" value={due} onChange={(e) => setDue(e.currentTarget.value)} />
            </Group>
            <Textarea label="Notes" autosize minRows={2} value={notes} onChange={(e) => setNotes(e.currentTarget.value)} maxLength={4000} />
            {create.isError ? (
              <Text c="red" size="sm" role="alert">
                {errorMessage(create.error)}
              </Text>
            ) : null}
            <Group justify="flex-end" gap="xs">
              <Button variant="default" onClick={() => setAdding(false)}>
                Cancel
              </Button>
              <Button type="submit" loading={create.isPending} disabled={!title.trim()}>
                Add task
              </Button>
            </Group>
          </Stack>
        </form>
      ) : null}
    </Panel>
  );
}

function TaskRow({ t, onToggle, pending }: { t: Task; onToggle: (done: boolean) => void; pending: boolean }) {
  const done = t.status === "done";
  const overdue = !done && t.due_date && t.due_date < new Date().toISOString().slice(0, 10);
  return (
    <div className={classes.task}>
      <Checkbox
        checked={done}
        disabled={pending}
        onChange={(e) => onToggle(e.currentTarget.checked)}
        aria-label={done ? `Reopen task: ${t.title}` : `Mark done: ${t.title}`}
        mt={2}
      />
      <div>
        <div className={done ? classes.taskDone : undefined}>{t.title}</div>
        <div className={classes.taskMeta}>
          {[t.owner ? `Owner: ${t.owner}` : null, t.due_date ? `Due ${formatDay(t.due_date + "T12:00:00")}` : null]
            .filter(Boolean)
            .join(", ")}
          {overdue ? <strong style={{ color: "var(--sn-danger)" }}> Overdue</strong> : null}
        </div>
        {t.notes ? <Text size="xs" c="dimmed" mt={2} className={classes.prose}>{t.notes}</Text> : null}
      </div>
      {done ? (
        <IconCircleCheck size={16} color="var(--sn-good)" aria-label="Done" />
      ) : (
        <span />
      )}
    </div>
  );
}
