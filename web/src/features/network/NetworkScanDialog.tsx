import { Alert, Button, Checkbox, Group, List, Modal, NumberInput, SegmentedControl, Select, Stack, Text, Textarea } from "@mantine/core";
import { IconAlertTriangle, IconEye } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { errorMessage } from "../../api/client";
import type { NetworkScanRequest } from "../../api/types";
import { formatDuration } from "../../lib/format";
import { useDevices } from "../devices/api";
import { usePreviewNetworkScan, useStartNetworkScan } from "./api";
import classes from "./Network.module.css";

type Kind = NetworkScanRequest["kind"];

const KINDS: { value: Kind; label: string; placeholder: string }[] = [
  { value: "discovery", label: "Port discovery", placeholder: "192.168.1.0/24\n192.168.1.10" },
  { value: "tls", label: "TLS certificates", placeholder: "nas.local:443\n192.168.1.10:8443" },
  { value: "headers", label: "HTTP headers", placeholder: "https://router.lan/\nhttp://192.168.1.10:8080/" },
];

/** Network scans run only after the person has read the server's preview and acknowledged it. */
export function NetworkScanDialog({ opened, onClose, deviceId }: { opened: boolean; onClose: () => void; deviceId: number | null }) {
  const devices = useDevices();
  const preview = usePreviewNetworkScan();
  const start = useStartNetworkScan();
  const navigate = useNavigate();
  const [device, setDevice] = useState<string | null>(deviceId ? String(deviceId) : null);
  const [kind, setKind] = useState<Kind>("discovery");
  const [targets, setTargets] = useState("");
  const [topPorts, setTopPorts] = useState<number>(100);
  const [ack, setAck] = useState(false);

  const request: NetworkScanRequest | null = useMemo(() => {
    const list = targets.split(/\r?\n/).map((t) => t.trim()).filter(Boolean);
    if (!device || list.length === 0) return null;
    return { device_id: Number(device), kind, targets: list, top_ports: kind === "discovery" ? topPorts : null };
  }, [device, kind, targets, topPorts]);
  const requestKey = JSON.stringify(request);

  // Any change to what would be scanned invalidates the preview and the acknowledgment.
  useEffect(() => {
    preview.reset();
    setAck(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestKey]);

  useEffect(() => {
    if (opened) {
      start.reset();
      if (deviceId) setDevice(String(deviceId));
      else if (!device && devices.data?.length) setDevice(String(devices.data[0].id));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opened, devices.data]);

  const p = preview.data;
  return (
    <Modal opened={opened} onClose={onClose} title="New network scan" size="xl">
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          The chosen device's agent runs the scan from its own network position. Every target must be inside the enabled
          scope.
        </Text>
        <Group grow align="flex-start">
          <Select
            label="Run from device"
            data={(devices.data ?? []).map((d) => ({ value: String(d.id), label: d.name }))}
            value={device}
            onChange={setDevice}
            required
          />
          <div>
            <Text size="sm" fw={500} mb={4}>
              Scan type
            </Text>
            <SegmentedControl fullWidth data={KINDS.map(({ value, label }) => ({ value, label }))} value={kind} onChange={(v) => setKind(v as Kind)} />
          </div>
        </Group>
        <Textarea
          label="Targets"
          description="One per line."
          placeholder={KINDS.find((k) => k.value === kind)?.placeholder}
          autosize
          minRows={3}
          maxRows={8}
          value={targets}
          onChange={(e) => setTargets(e.currentTarget.value)}
          classNames={{ input: "sn-mono" }}
        />
        {kind === "discovery" ? (
          <NumberInput label="Most common ports to try" min={10} max={1000} step={10} value={topPorts} onChange={(v) => setTopPorts(typeof v === "number" ? v : 100)} w={240} />
        ) : null}
        <Group>
          <Button variant="default" leftSection={<IconEye size={16} />} disabled={!request} loading={preview.isPending} onClick={() => request && preview.mutate(request)}>
            Preview what will run
          </Button>
        </Group>
        {preview.isError ? (
          <Alert color="red" variant="light" role="alert">
            {errorMessage(preview.error)}
          </Alert>
        ) : null}
        {p ? (
          <div className={classes.preview} data-testid="network-preview">
            <Text fw={650} size="sm">
              What this scan does
            </Text>
            <Text size="sm">{p.behavior}</Text>
            {p.commands.length ? (
              <>
                <Text fw={650} size="sm" mt="xs">
                  Exact commands the agent runs
                </Text>
                <pre className={classes.commands}>{p.commands.join("\n")}</pre>
              </>
            ) : (
              <Text size="sm" c="dimmed">
                No external program is started; the agent's built-in check (<span className="sn-mono">{p.check_id}</span>) makes the connections itself.
              </Text>
            )}
            {p.warnings.length ? (
              <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={18} />} mt="xs">
                <List size="sm" spacing={4}>
                  {p.warnings.map((w) => (
                    <List.Item key={w}>{w}</List.Item>
                  ))}
                </List>
              </Alert>
            ) : null}
            <Text size="xs" c="dimmed" mt="xs">
              Estimated time: about {formatDuration(p.estimated_seconds * 1000)}. {p.estimate_note}
            </Text>
            <Checkbox
              mt="sm"
              checked={ack}
              onChange={(e) => setAck(e.currentTarget.checked)}
              label="I've reviewed the commands and behavior above, and I'm authorized to scan these targets."
            />
          </div>
        ) : null}
        {start.isError ? (
          <Alert color="red" variant="light" role="alert">
            {errorMessage(start.error)}
          </Alert>
        ) : null}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={!p || !ack || !request}
            loading={start.isPending}
            onClick={() =>
              request &&
              start.mutate(
                { ...request, acknowledged: true },
                {
                  onSuccess: (scan) => {
                    onClose();
                    navigate(`/scans/${scan.id}`);
                  },
                },
              )
            }
          >
            Start network scan
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
