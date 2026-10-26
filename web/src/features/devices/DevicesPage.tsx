import { Button, Switch, Table, Text, Tooltip } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconPlus } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import type { DeviceSummary } from "../../api/types";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { RowLink } from "../../components/RowLink";
import { SeverityGlyph } from "../../components/Severity";
import { OnlineState, Tag } from "../../components/Status";
import { formatPercent, formatRelative } from "../../lib/format";
import { asSeverity, threatLabel } from "../../lib/severity";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "./api";
import { EnrollDialog } from "./EnrollDialog";

export function osLabel(d: DeviceSummary): string {
  const parts = [d.os_name, d.edition, d.os_version].filter(Boolean);
  return parts.join(" ");
}

export function ScoreCell({ d }: { d: DeviceSummary }) {
  if (d.score !== null) return <strong className="sn-num">{d.score}</strong>;
  const why =
    d.coverage === null
      ? "No posture scan has finished on this device yet."
      : `Only ${formatPercent(d.coverage)} of applicable checks completed in the latest posture scan.`;
  return (
    <Tooltip label={why}>
      <span tabIndex={0} className="sn-dim">
        Incomplete
      </span>
    </Tooltip>
  );
}

function pct(v: number | undefined): string {
  return typeof v === "number" ? `${v.toFixed(0)}%` : "–";
}

export function DevicesPage() {
  const [params, setParams] = useSearchParams();
  const [showRevoked, setShowRevoked] = useState(false);
  const devices = useDevices(showRevoked);
  const [enrollOpen, enroll] = useDisclosure(false);
  const { setDeviceId } = useDeviceScope();

  useEffect(() => {
    if (params.get("enroll") === "1") {
      enroll.open();
      setParams({}, { replace: true });
    }
  }, [params, setParams, enroll]);

  return (
    <>
      <PageHeader
        title="Devices"
        description="Enrolled devices, their health and security posture. Each device runs its own read-only agent."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={enroll.open}>
            Enroll a device
          </Button>
        }
      />
      <Panel
        padded={false}
        actions={<Switch size="xs" label="Show revoked" checked={showRevoked} onChange={(e) => setShowRevoked(e.currentTarget.checked)} />}
        title="Inventory"
      >
        {devices.isPending ? <Loading label="Loading devices" /> : null}
        {devices.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorState error={devices.error} onRetry={() => void devices.refetch()} />
          </div>
        ) : null}
        {devices.data && devices.data.length === 0 ? (
          <Empty title="No devices enrolled yet" action={<Button onClick={enroll.open}>Enroll a device</Button>}>
            Start with this computer. You'll get a one-time code and the exact command to run.
          </Empty>
        ) : null}
        {devices.data && devices.data.length > 0 ? (
          <div style={{ overflowX: "auto", marginTop: 8 }}>
            <Table miw={1040}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Device</Table.Th>
                  <Table.Th>State</Table.Th>
                  <Table.Th>Operating system</Table.Th>
                  <Table.Th>Agent</Table.Th>
                  <Table.Th>Score</Table.Th>
                  <Table.Th>Threat level</Table.Th>
                  <Table.Th>Open findings</Table.Th>
                  <Table.Th>CPU / memory</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {devices.data.map((d) => {
                  const threat = asSeverity(d.threat_level);
                  return (
                    <Table.Tr key={d.id}>
                      <Table.Td>
                        <RowLink to={`/devices/${d.id}`}>{d.name}</RowLink>
                        <Text size="xs" c="dimmed">
                          {d.hostname}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        {d.is_active ? (
                          <OnlineState online={d.online} lastSeen={d.last_seen_at ? formatRelative(d.last_seen_at) : undefined} />
                        ) : (
                          <Tag tone="danger">Revoked</Tag>
                        )}
                      </Table.Td>
                      <Table.Td>
                        {osLabel(d)}
                        <Text size="xs" c="dimmed">
                          {d.arch}
                          {d.os_build ? `, build ${d.os_build}` : ""}
                          {d.is_insider_build ? ", Insider build" : ""}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <span className="sn-mono">{d.agent_version}</span>
                        {d.agent_elevated ? (
                          <Text size="xs" c="dimmed">
                            Last ran elevated
                          </Text>
                        ) : null}
                      </Table.Td>
                      <Table.Td>
                        <ScoreCell d={d} />
                      </Table.Td>
                      <Table.Td>
                        <span style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 13 }}>
                          {threat ? <SeverityGlyph severity={threat} /> : null}
                          {threatLabel(d.threat_level)}
                        </span>
                      </Table.Td>
                      <Table.Td className="sn-num">
                        {d.open_findings > 0 && d.is_active ? (
                          <RowLink to="/vulnerabilities" onClick={() => setDeviceId(d.id)}>
                            {d.open_findings}
                          </RowLink>
                        ) : (
                          d.open_findings
                        )}
                      </Table.Td>
                      <Table.Td className="sn-num">
                        {Object.keys(d.latest_metrics).length ? (
                          `${pct(d.latest_metrics.cpu_percent)} / ${pct(d.latest_metrics.memory_percent)}`
                        ) : (
                          <span className="sn-dim">No readings</span>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </div>
        ) : null}
      </Panel>
      <Text size="xs" c="dimmed" mt="sm">
        Online means the agent checked in within the last two minutes.
      </Text>
      <EnrollDialog opened={enrollOpen} onClose={enroll.close} />
    </>
  );
}
