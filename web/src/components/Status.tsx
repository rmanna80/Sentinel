import { Loader, Tooltip } from "@mantine/core";
import {
  IconAlertTriangle,
  IconBan,
  IconCircleCheck,
  IconCircleDashed,
  IconCircleHalf2,
  IconCircleMinus,
  IconCircleX,
  IconClock,
  IconHourglass,
  IconPlayerPause,
  IconProgress,
  IconRotateClockwise,
  IconShieldCheck,
  IconUserCheck,
  type Icon,
} from "@tabler/icons-react";
import type { ReactNode } from "react";
import { humanize } from "../lib/format";
import classes from "./Status.module.css";

type Tone = "good" | "warn" | "danger" | "progress" | "neutral" | "accent";

interface StatusSpec {
  label: string;
  tone: Tone;
  icon: Icon | "spinner";
  hint?: string;
}

const SCAN: Record<string, StatusSpec> = {
  queued: { label: "Queued", tone: "neutral", icon: IconClock, hint: "Waiting for the device's agent to pick it up" },
  running: { label: "Running", tone: "progress", icon: "spinner" },
  completed: { label: "Completed", tone: "good", icon: IconCircleCheck },
  partial: { label: "Partial", tone: "warn", icon: IconCircleHalf2, hint: "Some checks did not finish" },
  failed: { label: "Failed", tone: "danger", icon: IconCircleX },
  cancelled: { label: "Cancelled", tone: "neutral", icon: IconBan },
};

const CHECK: Record<string, StatusSpec> = {
  planned: { label: "Waiting", tone: "neutral", icon: IconHourglass },
  passed: { label: "Passed", tone: "good", icon: IconCircleCheck, hint: "Ran and did not observe the problem it looks for" },
  failed: { label: "Issue found", tone: "danger", icon: IconAlertTriangle, hint: "Ran and found at least one problem" },
  skipped: { label: "Skipped", tone: "warn", icon: IconCircleDashed, hint: "Could not run; the reason is shown" },
  not_applicable: { label: "Not applicable", tone: "neutral", icon: IconCircleMinus },
  error: { label: "Error", tone: "danger", icon: IconCircleX },
  timeout: { label: "Timed out", tone: "danger", icon: IconHourglass },
  cancelled: { label: "Cancelled", tone: "neutral", icon: IconBan },
};

const FINDING: Record<string, StatusSpec> = {
  new: { label: "New", tone: "accent", icon: IconCircleDashed },
  confirmed: { label: "Confirmed", tone: "warn", icon: IconUserCheck },
  in_progress: { label: "In progress", tone: "progress", icon: IconProgress },
  accepted_risk: { label: "Accepted risk", tone: "neutral", icon: IconPlayerPause },
  resolved: { label: "Resolved", tone: "good", icon: IconShieldCheck, hint: "A re-run of the check passed" },
  reopened: { label: "Reopened", tone: "danger", icon: IconRotateClockwise, hint: "It was resolved, then seen again" },
};

const ALERT: Record<string, StatusSpec> = {
  new: { label: "New", tone: "accent", icon: IconCircleDashed },
  acknowledged: { label: "Acknowledged", tone: "warn", icon: IconUserCheck },
  investigating: { label: "Investigating", tone: "progress", icon: IconProgress },
  resolved: { label: "Resolved", tone: "good", icon: IconCircleCheck },
  false_positive: { label: "False positive", tone: "neutral", icon: IconCircleMinus },
};

const INCIDENT: Record<string, StatusSpec> = {
  open: { label: "Open", tone: "accent", icon: IconCircleDashed },
  investigating: { label: "Investigating", tone: "progress", icon: IconProgress },
  closed: { label: "Closed", tone: "good", icon: IconCircleCheck },
};

const SCHEDULE: Record<string, StatusSpec> = {
  enabled: { label: "On", tone: "good", icon: IconCircleCheck },
  disabled: { label: "Paused", tone: "neutral", icon: IconPlayerPause },
};

const TABLES = { scan: SCAN, check: CHECK, finding: FINDING, alert: ALERT, incident: INCIDENT, schedule: SCHEDULE } as const;
export type StatusKind = keyof typeof TABLES;

export function statusLabel(kind: StatusKind, value: string): string {
  return TABLES[kind][value]?.label ?? humanize(value);
}

export function StatusBadge({ kind, value, extra }: { kind: StatusKind; value: string; extra?: ReactNode }) {
  const spec: StatusSpec = TABLES[kind][value] ?? { label: humanize(value), tone: "neutral", icon: IconCircleDashed };
  const IconCmp = spec.icon;
  const body = (
    <span className={classes.status} data-tone={spec.tone}>
      {IconCmp === "spinner" ? (
        <Loader size={11} color="currentColor" type="oval" aria-hidden="true" />
      ) : (
        <IconCmp size={14} stroke={2} aria-hidden="true" />
      )}
      <span>{spec.label}</span>
      {extra}
    </span>
  );
  if (!spec.hint) return body;
  return (
    <Tooltip label={spec.hint}>
      <span className={classes.focusWrap} tabIndex={0}>
        {body}
      </span>
    </Tooltip>
  );
}

/** Generic small tag for categorical facts (scan type, finding kind, source). */
export function Tag({ children, tone = "neutral", title }: { children: ReactNode; tone?: Tone; title?: string }) {
  return (
    <span className={classes.tag} data-tone={tone} title={title}>
      {children}
    </span>
  );
}

export function OnlineState({ online, lastSeen }: { online: boolean; lastSeen?: string }) {
  return (
    <span className={classes.online} data-online={online ? "yes" : "no"}>
      <span className={classes.dot} aria-hidden="true" />
      {online ? "Online" : "Offline"}
      {!online && lastSeen ? <span className="sn-dim">, seen {lastSeen}</span> : null}
    </span>
  );
}
