import { Tooltip } from "@mantine/core";
import type { DetectionOut } from "../../api/types";
import { SeverityBadge } from "../../components/Severity";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import classes from "./Behavior.module.css";

/** A small status tag, shown only for the non-default states (mirrors how Advisories tags pinned/dismissed). */
export function StatusTag({ status }: { status: string }) {
  if (status === "acknowledged") return <Tag tone="warn">Acknowledged</Tag>;
  if (status === "dismissed") return <Tag tone="neutral">Dismissed</Tag>;
  return null;
}

/** ATT&CK chips: the technique id is the visible label, its name the tooltip (and accessible label). */
export function TechniqueChips({ ids, names }: { ids: string[]; names: string[] }) {
  if (!ids.length) return null;
  return (
    <>
      {ids.map((id, i) => {
        const name = names[i];
        const chip = (
          <Tag tone="neutral" title={name || undefined}>
            {id}
          </Tag>
        );
        if (!name) return <span key={id}>{chip}</span>;
        return (
          <Tooltip key={id} label={`${id} · ${name}`}>
            <span tabIndex={0} aria-label={`ATT&CK ${id}: ${name}`}>
              {chip}
            </span>
          </Tooltip>
        );
      })}
    </>
  );
}

/** One detection in the list: severity chip, title, rule id, ATT&CK chips, host, last seen and a repeat count. */
export function DetectionCard({ detection, onOpen }: { detection: DetectionOut; onOpen: () => void }) {
  return (
    <div className={classes.card}>
      <div className={classes.cardHead}>
        <SeverityBadge severity={detection.severity} />
        <span className={classes.title}>{detection.title}</span>
        <span className={classes.ruleId}>{detection.rule_id}</span>
        <StatusTag status={detection.status} />
      </div>
      <button
        type="button"
        className={classes.body}
        onClick={onOpen}
        aria-label={`Open detection: ${detection.title}`}
      >
        {detection.summary ? <div className={classes.summary}>{detection.summary}</div> : null}
        <div className={classes.chips}>
          <TechniqueChips ids={detection.technique_ids} names={detection.technique_names} />
          {detection.confidence ? (
            <Tag tone="neutral" title="Detection confidence">
              {humanize(detection.confidence)} confidence
            </Tag>
          ) : null}
        </div>
        <div className={classes.foot}>
          <span className="sn-mono">{detection.host}</span>
          <Time value={detection.last_ts} mode="relative" empty="Undated" />
          {detection.count > 1 ? <Tag tone="warn">{detection.count}×</Tag> : null}
          <span aria-hidden="true">· View evidence</span>
        </div>
      </button>
    </div>
  );
}
