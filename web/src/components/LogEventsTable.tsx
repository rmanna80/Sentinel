import { Table, Text, UnstyledButton } from "@mantine/core";
import type { LogEventOut } from "../api/types";
import { humanize } from "../lib/format";
import { SeverityBadge } from "./Severity";
import { Time } from "./Time";
import classes from "./LogEventsTable.module.css";

/** Normalized log events. Message text is rendered as plain text; it can contain attacker-controlled data. */
export function LogEventsTable({
  events,
  onOpen,
  showDevice,
  deviceNames,
}: {
  events: LogEventOut[];
  onOpen?: (id: number) => void;
  showDevice?: boolean;
  deviceNames?: Map<number, string>;
}) {
  return (
    <div className={classes.wrap}>
      <Table miw={showDevice ? 1040 : 900}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th w={170}>Time</Table.Th>
            <Table.Th w={100}>Severity</Table.Th>
            {showDevice ? <Table.Th>Device</Table.Th> : null}
            <Table.Th>Action</Table.Th>
            <Table.Th>User / source</Table.Th>
            <Table.Th>Message</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {events.map((e) => (
            <Table.Tr key={e.id}>
              <Table.Td>
                <Time value={e.occurred_at} mode="absolute" />
              </Table.Td>
              <Table.Td>
                <SeverityBadge severity={e.severity} variant="inline" />
              </Table.Td>
              {showDevice ? <Table.Td>{deviceNames?.get(e.device_id) ?? `Device ${e.device_id}`}</Table.Td> : null}
              <Table.Td>
                <span className={classes.action}>{humanize(e.action)}</span>
                {e.outcome ? <Text size="xs" c="dimmed">{humanize(e.outcome)}</Text> : null}
                <Text size="xs" c="dimmed">
                  {e.source}
                  {e.event_id ? ` ${e.event_id}` : ""}
                </Text>
              </Table.Td>
              <Table.Td>
                {e.user ? <div className="sn-mono">{e.user}</div> : null}
                {e.source_ip ? <div className="sn-mono sn-dim">{e.source_ip}</div> : null}
                {!e.user && !e.source_ip ? <span className="sn-dim">–</span> : null}
              </Table.Td>
              <Table.Td>
                {onOpen ? (
                  <UnstyledButton className={classes.msgBtn} onClick={() => onOpen(e.id)}>
                    {e.message}
                  </UnstyledButton>
                ) : (
                  <span className={classes.msg}>{e.message}</span>
                )}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </div>
  );
}
