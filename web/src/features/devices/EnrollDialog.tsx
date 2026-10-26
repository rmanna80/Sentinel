import { Alert, Button, Group, List, Modal, Stack, Text } from "@mantine/core";
import { useInterval } from "@mantine/hooks";
import { IconAlertCircle } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { errorMessage } from "../../api/client";
import type { EnrollmentCode } from "../../api/types";
import { CommandBox } from "../../components/CommandBox";
import { formatTime } from "../../lib/format";
import { useCreateEnrollmentCode } from "./api";

export function remainingSeconds(expiresAt: string, now: number): number {
  return Math.max(0, Math.floor((new Date(expiresAt).getTime() - now) / 1000));
}

export function formatCountdown(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

/** The code, its countdown and the exact command, as returned by the server. */
export function EnrollmentInstructions({ code, now = Date.now() }: { code: EnrollmentCode; now?: number }) {
  const left = remainingSeconds(code.expires_at, now);
  const expired = left === 0;
  return (
    <Stack gap="sm">
      <div>
        <Text size="xs" c="dimmed">
          One-time code
        </Text>
        <Text className="sn-mono" fz={26} fw={700} lts="0.06em" data-testid="enroll-code">
          {code.code}
        </Text>
        <Text size="sm" c={expired ? "red" : "dimmed"} role="timer" aria-live="off">
          {expired
            ? "This code has expired. Create a new one."
            : `Expires in ${formatCountdown(left)} (at ${formatTime(code.expires_at)}). It works once.`}
        </Text>
      </div>
      <div>
        <Text size="sm" fw={600} mb={6}>
          On the device, open PowerShell (or a terminal) in the Sentinel folder and run:
        </Text>
        <CommandBox command={code.command} />
      </div>
      <List size="sm" spacing={4} type="ordered">
        <List.Item>Run the command above. The agent registers and stores its own device token.</List.Item>
        <List.Item>
          Start the agent: <span className="sn-mono">scripts\start-agent.ps1</span> (or{" "}
          <span className="sn-mono">uv run sentinel-agent run</span>). It runs as you, without administrator rights.
        </List.Item>
        <List.Item>The device shows up in this list within a few seconds.</List.Item>
      </List>
    </Stack>
  );
}

export function EnrollDialog({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const create = useCreateEnrollmentCode();
  const [now, setNow] = useState(() => Date.now());
  const interval = useInterval(() => setNow(Date.now()), 1000);

  useEffect(() => {
    if (opened) {
      interval.start();
      if (!create.data && !create.isPending) create.mutate();
    } else {
      interval.stop();
      create.reset();
    }
    return interval.stop;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opened]);

  return (
    <Modal opened={opened} onClose={onClose} title="Enroll a device" size="lg">
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Enrolling installs nothing remotely. You run the agent yourself on the device you want Sentinel to check.
        </Text>
        {create.isPending ? <Text size="sm">Creating a one-time code…</Text> : null}
        {create.isError ? (
          <Alert color="red" variant="light" icon={<IconAlertCircle size={18} />} role="alert">
            {errorMessage(create.error)}
          </Alert>
        ) : null}
        {create.data ? <EnrollmentInstructions code={create.data} now={now} /> : null}
        <Group justify="flex-end">
          <Button variant="default" onClick={() => create.mutate()} loading={create.isPending}>
            New code
          </Button>
          <Button onClick={onClose}>Done</Button>
        </Group>
      </Stack>
    </Modal>
  );
}
