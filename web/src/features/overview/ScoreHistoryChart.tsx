import { SegmentedControl, Text } from "@mantine/core";
import { useMemo } from "react";
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DeviceSummary, ScorePoint } from "../../api/types";
import { ChartTooltipBody, LegendKey, type TooltipRow } from "../../components/ChartTooltip";
import { Empty } from "../../components/Page";
import { useChartColors } from "../../lib/chartTheme";
import { formatDateTime, formatDay, formatPercent } from "../../lib/format";
import classes from "./Overview.module.css";

export const HISTORY_RANGES = [
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
];

interface Point {
  t: number;
  scan_id: number;
  device: string;
  score: number | null;
  raw: number | null;
  coverage: number | null;
}

/**
 * Score per completed posture scan. "Score" is null (a gap) where coverage was too low; "Raw" is what the
 * open findings alone give. One device at a time keeps the lines readable; with several devices the points
 * are plotted in time order and the tooltip names the device.
 */
export function ScoreHistoryChart({
  history,
  devices,
  days,
  onDaysChange,
}: {
  history: ScorePoint[];
  devices: Pick<DeviceSummary, "id" | "name">[];
  days: number;
  /** Omit to hide the range control (the page already has one). */
  onDaysChange?: (d: number) => void;
}) {
  const c = useChartColors();
  const names = useMemo(() => new Map(devices.map((d) => [d.id, d.name])), [devices]);
  const data: Point[] = useMemo(
    () =>
      history
        .map((p) => ({
          t: new Date(p.ts).getTime(),
          scan_id: p.scan_id,
          device: names.get(p.device_id) ?? `Device ${p.device_id}`,
          score: p.score,
          raw: p.raw_score,
          coverage: p.coverage,
        }))
        .sort((a, b) => a.t - b.t),
    [history, names],
  );
  const gaps = data.filter((p) => p.score === null).length;

  return (
    <div>
      <div className={classes.chartHead}>
        <div className={classes.legend}>
          <LegendKey color={c.accent} label="Score" />
          <LegendKey color={c.muted} label="Raw score (findings only)" dashed />
        </div>
        {onDaysChange ? (
          <SegmentedControl
            size="xs"
            aria-label="History range"
            data={HISTORY_RANGES}
            value={String(days)}
            onChange={(v) => onDaysChange(Number(v))}
          />
        ) : null}
      </div>
      {data.length === 0 ? (
        <Empty title="No completed posture scans in this range">
          Score history fills in as full or posture scans complete. Try a longer range or run a scan.
        </Empty>
      ) : (
        <>
          <div aria-hidden="true">
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={data} margin={{ top: 10, right: 12, bottom: 0, left: -18 }}>
                <CartesianGrid stroke={c.grid} vertical={false} />
                <XAxis
                  dataKey="t"
                  type="number"
                  scale="time"
                  domain={["dataMin", "dataMax"]}
                  tickFormatter={(t: number) => formatDay(new Date(t).toISOString())}
                  tick={{ fill: c.tick, fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: c.axis }}
                  minTickGap={28}
                  padding={{ left: 8, right: 8 }}
                />
                <YAxis
                  domain={[0, 100]}
                  ticks={[0, 25, 50, 75, 100]}
                  tick={{ fill: c.tick, fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <ReferenceLine y={100} stroke={c.axis} />
                <Tooltip
                  cursor={{ stroke: c.axis, strokeWidth: 1 }}
                  content={({ active, payload }) => {
                    const p = active && payload?.[0] ? (payload[0].payload as Point) : null;
                    if (!p) return null;
                    const rows: TooltipRow[] = [
                      { key: "s", color: c.accent, label: "Score", value: p.score ?? "Incomplete" },
                      { key: "r", color: c.muted, label: "Raw score", value: p.raw ?? "Unavailable", dashed: true },
                    ];
                    return (
                      <ChartTooltipBody
                        title={formatDateTime(new Date(p.t).toISOString())}
                        rows={rows}
                        footer={`${p.device}, scan ${p.scan_id}, coverage ${formatPercent(p.coverage)}`}
                      />
                    );
                  }}
                />
                <Line
                  type="linear"
                  dataKey="raw"
                  stroke={c.muted}
                  strokeWidth={1.5}
                  strokeDasharray="4 3"
                  dot={false}
                  connectNulls
                  isAnimationActive={false}
                />
                <Line
                  type="linear"
                  dataKey="score"
                  stroke={c.accent}
                  strokeWidth={2}
                  dot={{ r: 3.5, fill: c.accent, stroke: c.surface, strokeWidth: 2 }}
                  activeDot={{ r: 5, fill: c.accent, stroke: c.surface, strokeWidth: 2 }}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          {gaps > 0 ? (
            <Text size="xs" c="dimmed" mt={4}>
              Gaps in the score line are scans where too few checks completed to give a score ({gaps} of {data.length}).
            </Text>
          ) : null}
          <table className="sr-only-table">
            <caption>Score history</caption>
            <thead>
              <tr>
                <th>Completed</th>
                <th>Device</th>
                <th>Score</th>
                <th>Raw score</th>
                <th>Coverage</th>
              </tr>
            </thead>
            <tbody>
              {data.map((p) => (
                <tr key={p.scan_id}>
                  <td>{formatDateTime(new Date(p.t).toISOString())}</td>
                  <td>{p.device}</td>
                  <td>{p.score ?? "Incomplete"}</td>
                  <td>{p.raw ?? "Unavailable"}</td>
                  <td>{formatPercent(p.coverage)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
