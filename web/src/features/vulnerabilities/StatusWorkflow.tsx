import { Alert, Button, Group, Radio, Stack, Text, Textarea } from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import type { FindingUpdate } from "../../api/types";
import { StatusBadge } from "../../components/Status";
import { statusChoices } from "./workflow";

export interface StatusWorkflowProps {
  status: string;
  allowedStatuses: string[];
  onSubmit: (body: FindingUpdate) => void;
  pending?: boolean;
  error?: unknown;
}

/** Change a finding's status with an optional note. Offers only allowed_statuses, never "resolved". */
export function StatusWorkflow({ status, allowedStatuses, onSubmit, pending, error }: StatusWorkflowProps) {
  const choices = statusChoices(allowedStatuses);
  const [next, setNext] = useState<string | null>(null);
  const [note, setNote] = useState("");

  return (
    <Stack gap="sm">
      <Group gap="xs">
        <Text size="sm" c="dimmed">
          Current status
        </Text>
        <StatusBadge kind="finding" value={status} />
      </Group>
      {choices.length === 0 ? (
        <Text size="sm" c="dimmed">
          {status === "resolved"
            ? "A re-run of the check passed, so this finding is closed. If the problem returns, the finding reopens on its own."
            : "No status changes are available."}
        </Text>
      ) : (
        <Radio.Group
          label="Change status to"
          value={next}
          onChange={setNext}
          name="finding-status"
          aria-describedby="resolve-explainer"
        >
          <Stack gap={8} mt={6}>
            {choices.map((c) => (
              <Radio key={c.value} value={c.value} label={c.label} description={c.description} />
            ))}
          </Stack>
        </Radio.Group>
      )}
      {choices.length > 0 ? (
        <Textarea
          label="Note"
          description="Saved to this finding's history."
          autosize
          minRows={2}
          maxRows={6}
          maxLength={4000}
          value={note}
          onChange={(e) => setNote(e.currentTarget.value)}
        />
      ) : null}
      <Alert variant="light" color="gray" icon={<IconInfoCircle size={16} />} id="resolve-explainer" p="xs">
        <Text size="xs">
          There's no "Resolved" option on purpose. Fix the problem, then use <strong>Verify</strong>: it re-runs the check
          that found it, and only a passing re-run resolves the finding.
        </Text>
      </Alert>
      {error ? (
        <Text size="sm" c="red" role="alert">
          {errorMessage(error)}
        </Text>
      ) : null}
      {choices.length > 0 ? (
        <Group justify="flex-end" gap="sm">
          <Button
            variant="default"
            disabled={!note.trim() || pending}
            onClick={() => onSubmit({ note: note.trim() })}
          >
            Add note only
          </Button>
          <Button
            disabled={!next}
            loading={pending}
            onClick={() => {
              if (!next) return;
              onSubmit({ status: next as FindingUpdate["status"], note: note.trim() || null });
              setNote("");
              setNext(null);
            }}
          >
            Update status
          </Button>
        </Group>
      ) : null}
    </Stack>
  );
}
