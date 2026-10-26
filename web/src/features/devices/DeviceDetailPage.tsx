import { Alert, Anchor, Button, Group, Modal, Stack, Table, Text, TextInput } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconActivityHeartbeat, IconAlertTriangle, IconPencil, IconRadar, IconTrash } from "@tabler/icons-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { errorMessage } from "../../api/client";
import type { DeviceSummary } from "../../api/types";
import { DemoBadge, isFixture } from "../../components/DemoData";
import { Facts } from "../../components/Facts";
import { Meter } from "../../components/Meter";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { RowLink } from "../../components/RowLink";
import { SeverityBadge, SeverityGlyph } from "../../components/Severity";
import { OnlineState, StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { formatPercent, humanize } from "../../lib/format";
import { asSeverity, SEVERITIES, SEVERITY_LABEL, threatLabel } from "../../lib/severity";
import { useDeviceScope } from "../../layout/DeviceScope";
import { NewScanDialog } from "../scans/NewScanDialog";
import { useScans } from "../scans/api";
import { useFindings } from "../vulnerabilities/api";
import { useDevice, useRenameDevice, useRevokeDevice } from "./api";
import { osLabel, ScoreCell } from "./DevicesPage";

export function DeviceDetailPage() {
  const id = Number(useParams().deviceId);
  const device = useDevice(id);
  if (!Number.isInteger(id) || id <= 0) return <ErrorState error={new Error("That device link isn't valid.")} />;
  if (device.isPending) return <Loading label="Loading device" />;
  if (device.isError) return <ErrorState error={device.error} onRetry={() => void device.refetch()} />;
  return <DeviceBody d={device.data} />;
}

function disks(metrics: Record<string, number>): [string, number][] {
  return Object.entries(metrics)
    .filter(([k]) => k === "disk_percent" || k.startsWith("disk_percent:"))
    .map(([k, v]): [string, number] => [k === "disk_percent" ? "Disk" : k.slice("disk_percent:".length), v]);
}

function DeviceBody({ d }: { d: DeviceSummary }) {
  const [scanOpen, scan] = useDisclosure(false);
  const [renameOpen, rename] = useDisclosure(false);
  const [revokeOpen, revoke] = useDisclosure(false);
  const { setDeviceId } = useDeviceScope();
  const navigate = useNavigate();
  const findings = useFindings({ device_id: d.id, status: "open", sort: "severity", limit: 8, offset: 0 });
  const scans = useScans({ device_id: d.id, limit: 6, offset: 0 });
  const threat = asSeverity(d.threat_level);
  const diskList = disks(d.latest_metrics);

  return (
    <>
      <PageHeader
        title={d.name}
        docTitle={d.name}
        meta={
          <>
            {d.is_active ? <OnlineState online={d.online} /> : <Tag tone="danger">Revoked</Tag>}
            <span>{d.hostname}</span>
            <span>
              Last seen <Time value={d.last_seen_at} mode="relative" />
            </span>
          </>
        }
        actions={
          d.is_active ? (
            <>
              <Button leftSection={<IconRadar size={16} />} onClick={scan.open}>
                Scan now
              </Button>
              <Button variant="default" leftSection={<IconPencil size={16} />} onClick={rename.open}>
                Rename
              </Button>
              <Button variant="default" color="red" leftSection={<IconTrash size={16} />} onClick={revoke.open}>
                Revoke
              </Button>
            </>
          ) : null
        }
      />
      {!d.is_active ? (
        <Alert color="gray" variant="light" mb="md" icon={<IconAlertTriangle size={18} />}>
          This device was revoked. Its history is kept, but its agent can't upload anything until it enrolls again.
        </Alert>
      ) : null}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
        <Panel title="Posture">
          <Group gap="xl" align="flex-start" mb="sm">
            <div>
              <Text size="xs" c="dimmed">
                Score
              </Text>
              <Text fz={28} fw={700}>
                <ScoreCell d={d} />
              </Text>
            </div>
            <div>
              <Text size="xs" c="dimmed">
                Threat level
              </Text>
              <Group gap={6} mt={8}>
                {threat ? <SeverityGlyph severity={threat} size={14} /> : null}
                <Text fw={650}>{threatLabel(d.threat_level)}</Text>
              </Group>
            </div>
            <div>
              <Text size="xs" c="dimmed">
                Coverage
              </Text>
              <Text fw={650} mt={6}>
                {d.coverage === null ? <span className="sn-dim">No posture scan yet</span> : formatPercent(d.coverage)}
              </Text>
            </div>
          </Group>
          <Text size="xs" c="dimmed" mb={6}>
            Open findings that count toward the score
          </Text>
          <Group gap="md">
            {SEVERITIES.filter((s) => s !== "info").map((s) => (
              <span key={s} style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 13 }}>
                <SeverityGlyph severity={s} />
                {SEVERITY_LABEL[s]} <strong className="sn-num">{d.counts[s] ?? 0}</strong>
              </span>
            ))}
          </Group>
        </Panel>
        <Panel
          title="Health"
          actions={
            <Anchor
              component={Link}
              to="/diagnostics"
              size="xs"
              fw={600}
              onClick={() => setDeviceId(d.id)}
            >
              <IconActivityHeartbeat size={13} style={{ verticalAlign: -2 }} /> Charts
            </Anchor>
          }
        >
          {Object.keys(d.latest_metrics).length === 0 ? (
            <Text size="sm" c="dimmed">
              No readings yet. The agent reports CPU, memory and disk while it runs.
            </Text>
          ) : (
            <Stack gap={8}>
              <Meter label="CPU" value={d.latest_metrics.cpu_percent} />
              <Meter label="Memory" value={d.latest_metrics.memory_percent} />
              {diskList.map(([name, v]) => (
                <Meter key={name} label={name} value={v} />
              ))}
            </Stack>
          )}
        </Panel>
        <Panel title="System">
          <Facts
            items={[
              ["Operating system", osLabel(d)],
              ["Build", d.os_build ?? "–"],
              ["Architecture", d.arch],
              ...(d.distro_id ? ([["Distribution", `${d.distro_id} ${d.distro_version ?? ""}`]] as [string, string][]) : []),
              ["Insider build", d.is_insider_build ? "Yes" : "No"],
              ["Agent", <span key="a" className="sn-mono">{d.agent_version}</span>],
              ["Enrolled", <Time key="e" value={d.enrolled_at} />],
            ]}
          />
        </Panel>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: 16, marginTop: 16 }}>
        <Panel
          title="Open findings"
          padded={false}
          actions={
            <Anchor component={Link} to="/vulnerabilities" size="xs" fw={600} onClick={() => setDeviceId(d.id)}>
              All for this device
            </Anchor>
          }
        >
          {findings.isPending ? <Loading /> : null}
          {findings.data?.items.length === 0 ? <Empty title="No open findings" /> : null}
          {findings.data && findings.data.items.length > 0 ? (
            <Table mt={8}>
              <Table.Tbody>
                {findings.data.items.map((f) => (
                  <Table.Tr key={f.id}>
                    <Table.Td w={110}>
                      <SeverityBadge severity={f.severity} />
                    </Table.Td>
                    <Table.Td>
                      <RowLink to={`/vulnerabilities/${f.id}`}>{f.title}</RowLink>
                    </Table.Td>
                    <Table.Td w={120}>
                      <StatusBadge kind="finding" value={f.status} />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          ) : null}
        </Panel>
        <Panel
          title="Recent scans"
          padded={false}
          actions={
            <Anchor component={Link} to={`/scans?device=${d.id}`} size="xs" fw={600}>
              All scans
            </Anchor>
          }
        >
          {scans.isPending ? <Loading /> : null}
          {scans.data?.items.length === 0 ? <Empty title="No scans yet" /> : null}
          {scans.data && scans.data.items.length > 0 ? (
            <Table mt={8}>
              <Table.Tbody>
                {scans.data.items.map((s) => (
                  <Table.Tr key={s.id}>
                    <Table.Td>
                      <RowLink to={`/scans/${s.id}`}>
                        {humanize(s.scan_type)} scan {s.id}
                      </RowLink>{" "}
                      {isFixture(s.data_mode) ? <DemoBadge /> : null}
                    </Table.Td>
                    <Table.Td>
                      <StatusBadge kind="scan" value={s.status} />
                    </Table.Td>
                    <Table.Td>
                      <Time value={s.requested_at} mode="relative" />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          ) : null}
        </Panel>
      </div>

      <NewScanDialog opened={scanOpen} onClose={scan.close} initialDeviceId={d.id} />
      <RenameDialog d={d} opened={renameOpen} onClose={rename.close} />
      <RevokeDialog
        d={d}
        opened={revokeOpen}
        onClose={revoke.close}
        onRevoked={() => {
          setDeviceId(null);
          navigate("/devices");
        }}
      />
    </>
  );
}

function RenameDialog({ d, opened, onClose }: { d: DeviceSummary; opened: boolean; onClose: () => void }) {
  const mut = useRenameDevice(d.id);
  const [name, setName] = useState(d.name);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    mut.mutate({ name: name.trim() }, { onSuccess: () => { onClose(); notifications.show({ message: "Device renamed" }); } });
  };
  return (
    <Modal opened={opened} onClose={onClose} title="Rename device" size="sm">
      <form onSubmit={submit}>
        <Stack gap="sm">
          <TextInput
            label="Name"
            description={`Shown in Sentinel only. The hostname stays ${d.hostname}.`}
            value={name}
            onChange={(e) => setName(e.currentTarget.value)}
            maxLength={255}
            required
            data-autofocus
          />
          {mut.isError ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(mut.error)}
            </Text>
          ) : null}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={mut.isPending} disabled={!name.trim() || name.trim() === d.name}>
              Rename
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function RevokeDialog({
  d,
  opened,
  onClose,
  onRevoked,
}: {
  d: DeviceSummary;
  opened: boolean;
  onClose: () => void;
  onRevoked: () => void;
}) {
  const mut = useRevokeDevice(d.id);
  const [typed, setTyped] = useState("");
  return (
    <Modal opened={opened} onClose={onClose} title={`Revoke ${d.name}?`} size="md">
      <Stack gap="sm">
        <Text size="sm">
          The device's agent token stops working immediately and queued scans for it are cancelled. Its scans, findings
          and history are kept. To use it again, enroll it with a new code.
        </Text>
        <TextInput
          label={`Type the device name (${d.name}) to confirm`}
          value={typed}
          onChange={(e) => setTyped(e.currentTarget.value)}
          autoComplete="off"
          data-autofocus
        />
        {mut.isError ? (
          <Text c="red" size="sm" role="alert">
            {errorMessage(mut.error)}
          </Text>
        ) : null}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Keep device
          </Button>
          <Button
            color="red"
            disabled={typed.trim() !== d.name}
            loading={mut.isPending}
            onClick={() =>
              mut.mutate(undefined, {
                onSuccess: () => {
                  notifications.show({ message: `${d.name} revoked` });
                  onClose();
                  onRevoked();
                },
              })
            }
          >
            Revoke device
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
