import { Text } from "@mantine/core";
import type { BehaviorSummary } from "../../api/types";
import classes from "./Behavior.module.css";

function Tile({
  label,
  value,
  note,
  highlight,
}: {
  label: string;
  value: number;
  note?: string;
  highlight?: "warn" | "danger";
}) {
  return (
    <div className={classes.tile} data-highlight={value > 0 ? highlight : undefined}>
      <div className={classes.tileLabel}>{label}</div>
      <div className={classes.tileValue}>{value}</div>
      {note ? <div className={classes.tileNote}>{note}</div> : null}
    </div>
  );
}

function sevCount(by: Record<string, number>, key: string): number {
  return typeof by[key] === "number" ? by[key] : 0;
}

/** Four tiles from the summary. Critical turns red and High amber when above zero. The `note` is a caption. */
export function BehaviorSummaryTiles({ summary }: { summary: BehaviorSummary }) {
  return (
    <div>
      <div className={classes.tiles}>
        <Tile label="New" value={summary.new} note="Awaiting triage" />
        <Tile label="Critical" value={sevCount(summary.by_severity, "critical")} note="Open detections" highlight="danger" />
        <Tile label="High" value={sevCount(summary.by_severity, "high")} note="Open detections" highlight="warn" />
        <Tile label="Hosts" value={summary.hosts} note="With detections" />
      </div>
      {summary.note ? (
        <Text className={classes.note} mt="xs">
          {summary.note}
        </Text>
      ) : null}
    </div>
  );
}
