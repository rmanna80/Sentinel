import {
  Alert,
  Button,
  Checkbox,
  Group,
  Modal,
  Radio,
  ScrollArea,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle, IconShieldLock } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { errorMessage } from "../../api/client";
import type { CheckCatalogEntry, ScanCreate } from "../../api/types";
import { CommandBox } from "../../components/CommandBox";
import { humanize } from "../../lib/format";
import { useDevices } from "../devices/api";
import { useCheckCatalog, useCreateScan } from "./api";
import classes from "./Scans.module.css";

type Choice = "full" | "posture" | "inventory" | "logs" | "custom";

const TYPES: { value: Choice; label: string; description: string }[] = [
  { value: "full", label: "Full", description: "Posture, installed software and recent logs." },
  { value: "posture", label: "Posture", description: "Configuration checks only. This sets the security score." },
  { value: "inventory", label: "Inventory", description: "Installed software, matched against known vulnerabilities." },
  { value: "logs", label: "Logs", description: "Recent security-relevant log events." },
  { value: "custom", label: "Choose checks", description: "Pick individual checks for this device." },
];

export function NewScanDialog({
  opened,
  onClose,
  initialDeviceId,
}: {
  opened: boolean;
  onClose: () => void;
  initialDeviceId?: number | null;
}) {
  const devices = useDevices();
  const catalog = useCheckCatalog();
  const create = useCreateScan();
  const navigate = useNavigate();
  const [deviceId, setDeviceId] = useState<string | null>(initialDeviceId ? String(initialDeviceId) : null);
  const [type, setType] = useState<Choice>("full");
  const [selected, setSelected] = useState<string[]>([]);
  const [elevated, setElevated] = useState(false);
  const [filter, setFilter] = useState("");

  const active = useMemo(() => (devices.data ?? []).filter((d) => d.is_active), [devices.data]);

  useEffect(() => {
    if (!opened) return;
    create.reset();
    if (initialDeviceId) setDeviceId(String(initialDeviceId));
    else if (!deviceId && active.length === 1) setDeviceId(String(active[0].id));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opened, initialDeviceId, active.length]);

  const deviceChecks: CheckCatalogEntry[] = useMemo(() => {
    if (!deviceId) return [];
    const id = Number(deviceId);
    // Network and malware checks need scope settings and start from their own pages.
    return (catalog.data ?? []).filter(
      (c) => c.device_ids.includes(id) && !c.profiles.every((p) => p === "network" || p === "malware"),
    );
  }, [catalog.data, deviceId]);

  const grouped = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const map = new Map<string, CheckCatalogEntry[]>();
    for (const c of deviceChecks) {
      if (q && !`${c.title} ${c.id} ${c.category}`.toLowerCase().includes(q)) continue;
      const list = map.get(c.category) ?? [];
      list.push(c);
      map.set(c.category, list);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [deviceChecks, filter]);

  const needsElevation = deviceChecks.filter((c) => c.requires_elevation && (type !== "custom" || selected.includes(c.id)));
  const canSubmit = !!deviceId && (type !== "custom" || selected.length > 0);

  const submit = () => {
    if (!deviceId) return;
    const body: ScanCreate = {
      device_id: Number(deviceId),
      scan_type: type,
      check_ids: type === "custom" ? selected : null,
      elevated,
    };
    create.mutate(body, {
      onSuccess: (scan) => {
        notifications.show({
          title: "Scan queued",
          message: elevated
            ? "Run scripts\\elevated-scan.ps1 on that device to start it."
            : "The device's agent picks it up within a few seconds.",
        });
        onClose();
        navigate(`/scans/${scan.id}`);
      },
    });
  };

  return (
    <Modal opened={opened} onClose={onClose} title="New scan" size="lg">
      <Stack gap="md">
        <Select
          label="Device"
          placeholder={active.length ? "Choose a device" : "No devices enrolled"}
          data={active.map((d) => ({ value: String(d.id), label: `${d.name}${d.online ? "" : " (offline)"}` }))}
          value={deviceId}
          onChange={(v) => {
            setDeviceId(v);
            setSelected([]);
          }}
          required
          data-autofocus
        />
        {deviceId && !active.find((d) => String(d.id) === deviceId)?.online ? (
          <Text size="xs" c="dimmed">
            This device is offline. The scan waits in the queue until its agent connects.
          </Text>
        ) : null}

        <Radio.Group label="Scan type" value={type} onChange={(v) => setType(v as Choice)}>
          <div className={classes.typeGrid}>
            {TYPES.map((t) => (
              <Radio.Card key={t.value} value={t.value} className={classes.typeCard} radius="sm">
                <Group wrap="nowrap" align="flex-start" gap="sm">
                  <Radio.Indicator mt={2} />
                  <div>
                    <Text fw={650} size="sm">
                      {t.label}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {t.description}
                    </Text>
                  </div>
                </Group>
              </Radio.Card>
            ))}
          </div>
        </Radio.Group>

        {type === "custom" ? (
          <div>
            <Group justify="space-between" mb={6}>
              <Text size="sm" fw={600}>
                Checks <span className="sn-dim">({selected.length} selected)</span>
              </Text>
              <Group gap={6}>
                <Button size="compact-xs" variant="subtle" onClick={() => setSelected(deviceChecks.map((c) => c.id))}>
                  Select all
                </Button>
                <Button size="compact-xs" variant="subtle" onClick={() => setSelected([])}>
                  Clear
                </Button>
              </Group>
            </Group>
            {!deviceId ? (
              <Text size="sm" c="dimmed">
                Choose a device to see the checks its agent offers.
              </Text>
            ) : deviceChecks.length === 0 ? (
              <Text size="sm" c="dimmed">
                This device's agent hasn't reported its checks yet. Start the agent and try again.
              </Text>
            ) : (
              <>
                <TextInput
                  size="xs"
                  placeholder="Filter checks"
                  aria-label="Filter checks"
                  value={filter}
                  onChange={(e) => setFilter(e.currentTarget.value)}
                  mb={6}
                />
                <ScrollArea.Autosize mah={260} className={classes.checkList}>
                  <Checkbox.Group value={selected} onChange={setSelected} aria-label="Checks to run">
                    {grouped.map(([category, checks]) => (
                      <fieldset key={category} className={classes.checkGroup}>
                        <legend>{humanize(category)}</legend>
                        {checks.map((c) => (
                          <Checkbox
                            key={c.id}
                            value={c.id}
                            size="xs"
                            label={
                              <span>
                                {c.title}
                                {c.requires_elevation ? <span className={classes.adminTag}> needs admin</span> : null}
                              </span>
                            }
                            description={<span className="sn-mono">{c.id}</span>}
                          />
                        ))}
                      </fieldset>
                    ))}
                  </Checkbox.Group>
                </ScrollArea.Autosize>
              </>
            )}
          </div>
        ) : null}

        <div className={classes.elevated}>
          <Switch
            checked={elevated}
            onChange={(e) => setElevated(e.currentTarget.checked)}
            label="Run as administrator (elevated)"
            description={
              needsElevation.length
                ? `${needsElevation.length} check${needsElevation.length === 1 ? "" : "s"} in this scan need administrator rights; without elevation they are skipped and listed with that reason.`
                : "Some checks (disk encryption, Secure Boot, the Security event log) need administrator rights."
            }
          />
          {elevated ? (
            <Alert variant="light" color="iris" icon={<IconShieldLock size={18} />} mt="sm">
              <Text size="sm">
                The everyday agent never runs as administrator, so this scan waits until you start it yourself. On that
                device, run the script below. Windows shows its permission prompt; the agent takes this one scan, runs it
                read-only, and exits.
              </Text>
              <CommandBox command="scripts\elevated-scan.ps1" label="PowerShell" />
            </Alert>
          ) : null}
        </div>

        {create.isError ? (
          <Alert color="red" variant="light" icon={<IconAlertCircle size={18} />} role="alert">
            {errorMessage(create.error)}
          </Alert>
        ) : null}

        <Group justify="flex-end" gap="sm">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!canSubmit} loading={create.isPending}>
            Queue scan
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
