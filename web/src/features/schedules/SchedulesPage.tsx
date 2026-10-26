import { Button, Group, Modal, Select, Stack, Switch, Table, Text, TextInput, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconPencil, IconPlayerPlay, IconPlus, IconTrash } from "@tabler/icons-react";
import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { errorMessage } from "../../api/client";
import type { ScheduleCreate, ScheduleOut } from "../../api/types";
import { Empty, ErrorState, Loading, PageHeader, Panel } from "../../components/Page";
import { StatusBadge, Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import { humanize } from "../../lib/format";
import { useDeviceScope } from "../../layout/DeviceScope";
import { useDevices } from "../devices/api";
import { useCreateSchedule, useDeleteSchedule, useRunScheduleNow, useSchedules, useUpdateSchedule } from "./api";

const DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const FREQ = [
  { value: "hourly", label: "Every hour" },
  { value: "daily", label: "Every day" },
  { value: "weekly", label: "Every week" },
  { value: "monthly", label: "Every month" },
];
const TYPES = [
  { value: "full", label: "Full" },
  { value: "posture", label: "Posture" },
  { value: "inventory", label: "Inventory" },
  { value: "logs", label: "Logs" },
];

function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "America/New_York";
  } catch {
    return "America/New_York";
  }
}

interface ScheduleTiming {
  frequency: string;
  time_of_day: string;
  day_of_week?: number | null;
  day_of_month?: number | null;
  timezone: string;
}

export function describeSchedule(s: ScheduleTiming): string {
  const at = `at ${s.time_of_day} (${s.timezone})`;
  if (s.frequency === "hourly") return `Every hour, at minute ${s.time_of_day.slice(3)}`;
  if (s.frequency === "weekly") return `Every ${DAYS[s.day_of_week ?? 0]} ${at}`;
  if (s.frequency === "monthly") return `On day ${s.day_of_month ?? 1} of every month ${at}`;
  return `Every day ${at}`;
}

export function SchedulesPage() {
  const { deviceId } = useDeviceScope();
  const schedules = useSchedules(deviceId);
  const update = useUpdateSchedule();
  const runNow = useRunScheduleNow();
  const del = useDeleteSchedule();
  const [editing, setEditing] = useState<ScheduleOut | "new" | null>(null);
  const [deleting, setDeleting] = useState<ScheduleOut | null>(null);

  return (
    <>
      <PageHeader
        title="Scheduled tasks"
        description="Scans that run on a timetable. A scheduled scan the agent doesn't pick up within the grace period is reported as missed."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing("new")}>
            New schedule
          </Button>
        }
      />
      <Panel padded={false}>
        {schedules.isPending ? <Loading /> : null}
        {schedules.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorState error={schedules.error} onRetry={() => void schedules.refetch()} />
          </div>
        ) : null}
        {schedules.data && schedules.data.length === 0 ? (
          <Empty title="No schedules yet" action={<Button onClick={() => setEditing("new")}>New schedule</Button>}>
            A daily full scan keeps the score, inventory and logs current. Logs scans also feed threat detection.
          </Empty>
        ) : null}
        {update.isError || runNow.isError ? (
          <Text c="red" size="sm" p="md" role="alert">
            {errorMessage(update.error ?? runNow.error)}
          </Text>
        ) : null}
        {schedules.data && schedules.data.length > 0 ? (
          <div style={{ overflowX: "auto" }}>
            <Table miw={1040}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Schedule</Table.Th>
                  <Table.Th>Device</Table.Th>
                  <Table.Th>Scan</Table.Th>
                  <Table.Th>Next run</Table.Th>
                  <Table.Th>Last run</Table.Th>
                  <Table.Th>On</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {schedules.data.map((s) => (
                  <Table.Tr key={s.id}>
                    <Table.Td>
                      <div style={{ fontWeight: 600 }}>{s.name}</div>
                      <Text size="xs" c="dimmed">
                        {describeSchedule(s)}
                      </Text>
                    </Table.Td>
                    <Table.Td>{s.device_name ?? `Device ${s.device_id}`}</Table.Td>
                    <Table.Td>
                      <Tag>{humanize(s.scan_type)}</Tag>
                    </Table.Td>
                    <Table.Td>{s.enabled ? <Time value={s.next_run_at} empty="Not scheduled" /> : <span className="sn-dim">Paused</span>}</Table.Td>
                    <Table.Td>
                      {s.last_scan_id ? (
                        <Group gap={6}>
                          <Link to={`/scans/${s.last_scan_id}`} className="sn-link">
                            <Time value={s.last_run_at} mode="relative" />
                          </Link>
                          {s.last_scan_status ? <StatusBadge kind="scan" value={s.last_scan_status} /> : null}
                        </Group>
                      ) : (
                        <span className="sn-dim">Never</span>
                      )}
                      {s.consecutive_failures > 0 ? (
                        <Text size="xs" c="red">
                          {s.consecutive_failures} failed or missed in a row
                        </Text>
                      ) : null}
                    </Table.Td>
                    <Table.Td>
                      <Switch
                        checked={s.enabled}
                        aria-label={`${s.name}: ${s.enabled ? "on" : "paused"}`}
                        onChange={(e) => update.mutate({ id: s.id, body: { enabled: e.currentTarget.checked } })}
                      />
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4} wrap="nowrap" justify="flex-end">
                        <Tooltip label="Run now (the timetable doesn't change)">
                          <Button
                            size="compact-sm"
                            variant="subtle"
                            aria-label={`Run ${s.name} now`}
                            loading={runNow.isPending && runNow.variables === s.id}
                            onClick={() =>
                              runNow.mutate(s.id, {
                                onSuccess: (scan) =>
                                  notifications.show({
                                    message: (
                                      <span>
                                        Queued{" "}
                                        <Link to={`/scans/${scan.id}`} className="sn-link">
                                          scan {scan.id}
                                        </Link>
                                      </span>
                                    ),
                                  }),
                              })
                            }
                          >
                            <IconPlayerPlay size={15} />
                          </Button>
                        </Tooltip>
                        <Tooltip label="Edit">
                          <Button size="compact-sm" variant="subtle" aria-label={`Edit ${s.name}`} onClick={() => setEditing(s)}>
                            <IconPencil size={15} />
                          </Button>
                        </Tooltip>
                        <Tooltip label="Delete">
                          <Button size="compact-sm" variant="subtle" color="red" aria-label={`Delete ${s.name}`} onClick={() => setDeleting(s)}>
                            <IconTrash size={15} />
                          </Button>
                        </Tooltip>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
        ) : null}
      </Panel>
      <ScheduleDialog schedule={editing} onClose={() => setEditing(null)} />
      <Modal opened={deleting !== null} onClose={() => setDeleting(null)} title="Delete this schedule?" size="sm">
        <Text size="sm">{deleting?.name} stops running. Scans it already ran are kept.</Text>
        {del.isError ? (
          <Text c="red" size="sm" mt="sm" role="alert">
            {errorMessage(del.error)}
          </Text>
        ) : null}
        <Group justify="flex-end" mt="md">
          <Button variant="default" onClick={() => setDeleting(null)}>
            Keep it
          </Button>
          <Button color="red" loading={del.isPending} onClick={() => deleting && del.mutate(deleting.id, { onSuccess: () => setDeleting(null) })}>
            Delete schedule
          </Button>
        </Group>
      </Modal>
    </>
  );
}

function ScheduleDialog({ schedule, onClose }: { schedule: ScheduleOut | "new" | null; onClose: () => void }) {
  const devices = useDevices();
  const { deviceId: scoped } = useDeviceScope();
  const create = useCreateSchedule();
  const update = useUpdateSchedule();
  const isNew = schedule === "new";
  const [form, setForm] = useState<ScheduleCreate>({
    name: "",
    device_id: 0,
    scan_type: "full",
    frequency: "daily",
    time_of_day: "09:00",
    day_of_week: null,
    day_of_month: null,
    timezone: browserZone(),
    enabled: true,
  });

  useEffect(() => {
    create.reset();
    update.reset();
    if (schedule === "new") {
      const dev = scoped ?? devices.data?.[0]?.id ?? 0;
      setForm({ name: "Daily full scan", device_id: dev, scan_type: "full", frequency: "daily", time_of_day: "09:00", day_of_week: null, day_of_month: null, timezone: browserZone(), enabled: true });
    } else if (schedule) {
      setForm({
        name: schedule.name,
        device_id: schedule.device_id,
        scan_type: schedule.scan_type as ScheduleCreate["scan_type"],
        frequency: schedule.frequency as ScheduleCreate["frequency"],
        time_of_day: schedule.time_of_day,
        day_of_week: schedule.day_of_week,
        day_of_month: schedule.day_of_month,
        timezone: schedule.timezone,
        enabled: schedule.enabled,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [schedule]);

  const set = <K extends keyof ScheduleCreate>(k: K, v: ScheduleCreate[K]) => setForm((f) => ({ ...f, [k]: v }));
  const body: ScheduleCreate = {
    ...form,
    day_of_week: form.frequency === "weekly" ? (form.day_of_week ?? 0) : null,
    day_of_month: form.frequency === "monthly" ? (form.day_of_month ?? 1) : null,
  };
  const pending = create.isPending || update.isPending;
  const error = create.error ?? update.error;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const done = { onSuccess: () => { onClose(); notifications.show({ message: isNew ? "Schedule created" : "Schedule saved" }); } };
    if (isNew) create.mutate(body, done);
    else if (schedule) update.mutate({ id: schedule.id, body }, done);
  };

  return (
    <Modal opened={schedule !== null} onClose={onClose} title={isNew ? "New schedule" : "Edit schedule"} size="md">
      <form onSubmit={submit}>
        <Stack gap="sm">
          <TextInput label="Name" value={form.name} onChange={(e) => set("name", e.currentTarget.value)} maxLength={128} required data-autofocus />
          <Select
            label="Device"
            data={(devices.data ?? []).map((d) => ({ value: String(d.id), label: d.name }))}
            value={form.device_id ? String(form.device_id) : null}
            onChange={(v) => set("device_id", Number(v ?? 0))}
            required
          />
          <Select label="Scan type" data={TYPES} value={form.scan_type} onChange={(v) => v && set("scan_type", v as ScheduleCreate["scan_type"])} />
          <Group grow gap="sm" align="flex-start">
            <Select label="Repeat" data={FREQ} value={form.frequency} onChange={(v) => v && set("frequency", v as ScheduleCreate["frequency"])} />
            <TextInput
              label={form.frequency === "hourly" ? "Minute (HH:MM, minutes used)" : "Time"}
              type="time"
              value={form.time_of_day}
              onChange={(e) => set("time_of_day", e.currentTarget.value)}
              required
            />
          </Group>
          {form.frequency === "weekly" ? (
            <Select
              label="Day of the week"
              data={DAYS.map((d, i) => ({ value: String(i), label: d }))}
              value={String(form.day_of_week ?? 0)}
              onChange={(v) => set("day_of_week", Number(v ?? 0))}
            />
          ) : null}
          {form.frequency === "monthly" ? (
            <Select
              label="Day of the month"
              description="1 to 28, so it exists in every month."
              data={Array.from({ length: 28 }, (_, i) => ({ value: String(i + 1), label: String(i + 1) }))}
              value={String(form.day_of_month ?? 1)}
              onChange={(v) => set("day_of_month", Number(v ?? 1))}
            />
          ) : null}
          <TextInput
            label="Time zone"
            description="IANA name. Local time stays the same across daylight-saving changes."
            value={form.timezone}
            onChange={(e) => set("timezone", e.currentTarget.value)}
            required
          />
          <Text size="xs" c="dimmed">
            {describeSchedule(body)}
          </Text>
          {error ? (
            <Text c="red" size="sm" role="alert">
              {errorMessage(error)}
            </Text>
          ) : null}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={pending} disabled={!form.name.trim() || !form.device_id}>
              {isNew ? "Create schedule" : "Save"}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
