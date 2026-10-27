import { Alert, Anchor, Button, Group, Text } from "@mantine/core";
import { IconExternalLink, IconRefresh, IconRss } from "@tabler/icons-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import type { FeedStatus } from "../../api/types";
import { Panel } from "../../components/Page";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import classes from "./Advisories.module.css";

function asDate(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

const STATUS_TONE: Record<string, "good" | "danger" | "neutral" | "warn"> = {
  ok: "good",
  error: "danger",
  never: "neutral",
  disabled: "neutral",
};

export function FeedSummary({
  status,
  onRefresh,
  refreshing,
  refreshError,
}: {
  status: FeedStatus;
  onRefresh?: () => void;
  refreshing?: boolean;
  refreshError?: string | null;
}) {
  if (!status.enabled) {
    return (
      <Panel title="Threat-intelligence feed">
        <Alert color="yellow" variant="light" icon={<IconRss size={18} />} title="The feed is off">
          <Text size="sm" mb="sm">
            Advisories are security news from Hacker News, matched against your software inventory, KEV list and open
            findings. The feed is turned off, so nothing is being fetched.
          </Text>
          <Button
            component={Link}
            to="/integrations"
            size="xs"
            variant="default"
            leftSection={<IconExternalLink size={14} />}
          >
            Turn on the Hacker News feed under Integrations
          </Button>
        </Alert>
      </Panel>
    );
  }

  return (
    <Panel
      title="Threat-intelligence feed"
      description={
        <>
          Security news from Hacker News, matched to your inventory. It never changes a check or your devices. Manage the
          feed on the{" "}
          <Anchor component={Link} to="/integrations" size="xs">
            Integrations
          </Anchor>{" "}
          page.
        </>
      }
      actions={
        onRefresh ? (
          <Button
            size="xs"
            variant="default"
            leftSection={<IconRefresh size={14} />}
            onClick={onRefresh}
            loading={refreshing}
            disabled={!status.outbound_enabled}
          >
            Refresh now
          </Button>
        ) : null
      }
    >
      {!status.outbound_enabled ? (
        <Text size="xs" c="dimmed" mb="xs">
          Outbound connections are turned off for this server, so a refresh can't run right now.
        </Text>
      ) : null}
      {refreshError ? (
        <Text size="sm" c="red" role="alert" mb="xs">
          {refreshError}
        </Text>
      ) : null}
      <Group gap={28} wrap="wrap" align="flex-start">
        <Fact label="State" value={<Tag tone={STATUS_TONE[status.status] ?? "neutral"}>{status.status}</Tag>} />
        <Fact label="Advisories" value={status.total} />
        <Fact label="New" value={status.new_count} />
        <Fact label="Matched & open" value={status.matched_open} />
        <Fact label="Pinned" value={status.pinned} />
        <Fact label="Last synced" value={<Time value={asDate(status.last_synced_at)} mode="relative" empty="Never" />} />
      </Group>
      {status.detail ? (
        <Text size="xs" c="dimmed" mt="sm">
          {status.detail}
        </Text>
      ) : null}
    </Panel>
  );
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <div className={classes.summaryFactLabel}>{label}</div>
      <div className={classes.summaryFactValue} style={typeof value === "number" ? undefined : { fontSize: "var(--mantine-font-size-sm)" }}>
        {value}
      </div>
    </div>
  );
}
