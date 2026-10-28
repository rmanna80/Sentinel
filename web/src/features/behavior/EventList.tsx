import { Text } from "@mantine/core";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { detectionEvents } from "./evidence";
import classes from "./Behavior.module.css";

/** The triggering events, each as one readable row: kind, a short human summary, and the timestamp. */
export function EventList({ events }: { events: ReadonlyArray<Record<string, unknown>> | null | undefined }) {
  const rows = detectionEvents(events);
  if (!rows.length) {
    return (
      <Text size="sm" c="dimmed">
        No triggering events were recorded for this detection.
      </Text>
    );
  }
  return (
    <ul className={classes.events}>
      {rows.map((ev, i) => (
        <li key={i}>
          <div className={classes.eventHead}>
            <Tag tone="neutral">{ev.kindLabel}</Tag>
            <Text component="span" size="xs" c="dimmed">
              <Time value={ev.ts} mode="relative" empty="Undated" />
            </Text>
          </div>
          <div className={classes.eventSummary}>{ev.summary}</div>
        </li>
      ))}
    </ul>
  );
}
