import { Table, Text } from "@mantine/core";
import { useExplainCvss } from "../features/assistant/api";
import { ErrorState, Loading } from "./Page";

/** Plain-language reading of a CVSS vector, computed on the server without any model. */
export function CvssExplain({ vector }: { vector: string }) {
  const q = useExplainCvss(vector);
  if (q.isPending) return <Loading label="Reading the CVSS vector" />;
  if (q.isError) return <ErrorState error={q.error} title="Couldn't read this CVSS vector" />;
  const x = q.data;
  return (
    <div>
      <Text size="sm" mb="xs">
        {x.summary}
      </Text>
      <div style={{ overflowX: "auto" }}>
        <Table miw={520}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Metric</Table.Th>
              <Table.Th>Value</Table.Th>
              <Table.Th>What it means</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {x.metrics.map((m) => (
              <Table.Tr key={m.key}>
                <Table.Td>
                  {m.name} <span className="sn-mono sn-dim">{m.key}</span>
                </Table.Td>
                <Table.Td className="sn-mono">{m.value}</Table.Td>
                <Table.Td>{m.meaning}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </div>
      {x.missing_base_metrics.length ? (
        <Text size="xs" c="dimmed" mt={6}>
          Missing base metrics: {x.missing_base_metrics.join(", ")}.
        </Text>
      ) : null}
      {x.unrecognized.length ? (
        <Text size="xs" c="dimmed" mt={4}>
          Not recognized: <span className="sn-mono">{x.unrecognized.join(" ")}</span>
        </Text>
      ) : null}
      <Text size="xs" c="dimmed" mt={6}>
        {x.score_note}
      </Text>
    </div>
  );
}
