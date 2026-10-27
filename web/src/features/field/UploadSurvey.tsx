import { Alert, Button, FileButton, Group, Stack, Text, TextInput, Textarea } from "@mantine/core";
import { IconFileUpload, IconUpload } from "@tabler/icons-react";
import { useState } from "react";
import { Link } from "react-router";
import { errorMessage } from "../../api/client";
import type { CaptureDetail } from "../../api/types";
import { Panel } from "../../components/Page";
import { Tag } from "../../components/Status";
import { CLASSIFICATION } from "./classification";
import { useCreateCapture } from "./api";

function summaryCounts(summary: Record<string, unknown>): [string, number][] {
  const order = ["access_points", "rogue_suspects", "weak_own", "own", "known", "unknown", "open"];
  return order
    .map((k): [string, number] => [k, typeof summary[k] === "number" ? (summary[k] as number) : 0])
    .filter(([, v]) => v > 0);
}

const COUNT_LABEL: Record<string, string> = {
  access_points: "Access points",
  rogue_suspects: "Rogue suspects",
  weak_own: "Weak (yours)",
  own: "Yours",
  known: "Known",
  unknown: "Unknown",
  open: "Open",
};

/** Read an airodump-ng CSV from a file (or pasted text) in the browser and upload it as a Wi-Fi survey. */
export function UploadSurvey() {
  const create = useCreateCapture();
  const [label, setLabel] = useState("");
  const [csv, setCsv] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [result, setResult] = useState<CaptureDetail | null>(null);

  const readFile = (file: File | null) => {
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => setCsv(typeof reader.result === "string" ? reader.result : "");
    reader.readAsText(file);
  };

  const upload = () => {
    if (!csv.trim()) return;
    create.mutate(
      { kind: "wifi_survey", source_label: label.trim() || fileName || "Wi-Fi survey", notes: "", airodump_csv: csv },
      {
        onSuccess: (capture) => {
          setResult(capture);
          setCsv("");
          setFileName(null);
          setLabel("");
        },
      },
    );
  };

  return (
    <Panel
      title="Upload a Wi-Fi survey"
      description="An airodump-ng CSV you captured. It is read in your browser and sent to the local server, which classifies each access point against your known networks. This is passive survey data; Sentinel does not scan or transmit."
    >
      <Stack gap="md">
        <TextInput
          label="Source label"
          description="Where or when you captured this, for your own reference."
          placeholder="e.g. Office 3rd floor, Tuesday"
          value={label}
          onChange={(e) => setLabel(e.currentTarget.value)}
          maw={420}
        />
        <Group gap="sm" align="center">
          <FileButton onChange={readFile} accept=".csv,text/csv">
            {(props) => (
              <Button {...props} variant="default" leftSection={<IconFileUpload size={16} />}>
                Choose CSV file
              </Button>
            )}
          </FileButton>
          {fileName ? (
            <Text size="sm" c="dimmed">
              {fileName}
            </Text>
          ) : null}
        </Group>
        <Textarea
          label="Or paste the CSV"
          description="Paste the contents of an airodump-ng CSV here instead of choosing a file."
          autosize
          minRows={3}
          maxRows={10}
          value={csv}
          onChange={(e) => setCsv(e.currentTarget.value)}
        />
        {create.isError ? (
          <Text size="sm" c="red" role="alert">
            {errorMessage(create.error)}
          </Text>
        ) : null}
        <Group>
          <Button leftSection={<IconUpload size={16} />} onClick={upload} loading={create.isPending} disabled={!csv.trim()}>
            Upload survey
          </Button>
        </Group>

        {result ? (
          <Alert color="green" variant="light" title="Survey uploaded">
            <Text size="sm" mb="xs">
              {result.record_count} record{result.record_count === 1 ? "" : "s"} read from{" "}
              <strong>{result.source_label}</strong>. Classifications:
            </Text>
            <Group gap={8} mb="sm">
              {summaryCounts(result.summary).length === 0 ? (
                <Text size="sm" c="dimmed">
                  No access points were found in this file.
                </Text>
              ) : (
                summaryCounts(result.summary).map(([k, v]) => {
                  const cls = k === "access_points" || k === "open" ? undefined : CLASSIFICATION[k];
                  return (
                    <Tag key={k} tone={cls?.tone ?? "neutral"}>
                      {COUNT_LABEL[k] ?? k}: {v}
                    </Tag>
                  );
                })
              )}
            </Group>
            <Link to={`/field/${result.id}`} className="sn-link">
              View the capture
            </Link>
          </Alert>
        ) : null}
      </Stack>
    </Panel>
  );
}
