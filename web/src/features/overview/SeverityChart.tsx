import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartTooltipBody } from "../../components/ChartTooltip";
import { useChartColors } from "../../lib/chartTheme";
import { SEVERITIES, SEVERITY_LABEL, type Severity } from "../../lib/severity";
import classes from "./Overview.module.css";

interface Row {
  severity: Severity;
  label: string;
  count: number;
}

/** Open findings by severity: horizontal bars, value at the tip, with a table for screen readers. */
export function SeverityChart({ counts }: { counts: Record<string, number> }) {
  const c = useChartColors();
  const rows: Row[] = SEVERITIES.map((s) => ({ severity: s, label: SEVERITY_LABEL[s], count: counts[s] ?? 0 }));
  const total = rows.reduce((n, r) => n + r.count, 0);

  return (
    <div>
      <div className={classes.sevChart} aria-hidden="true">
        <ResponsiveContainer width="100%" height={176}>
          <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 36, bottom: 4, left: 0 }} barCategoryGap={8}>
            <XAxis type="number" hide allowDecimals={false} domain={[0, (max: number) => Math.max(1, max)]} />
            <YAxis
              type="category"
              dataKey="label"
              width={78}
              tickLine={false}
              axisLine={{ stroke: c.axis }}
              tick={{ fill: c.tick, fontSize: 12 }}
            />
            <Tooltip
              cursor={{ fill: c.accentWash }}
              content={({ active, payload }) => {
                const row = active && payload?.[0] ? (payload[0].payload as Row) : null;
                if (!row) return null;
                return (
                  <ChartTooltipBody
                    title={`${row.label} severity`}
                    rows={[{ key: "n", color: c.severity[row.severity], label: "Open findings", value: row.count }]}
                  />
                );
              }}
            />
            <Bar dataKey="count" maxBarSize={20} radius={[0, 4, 4, 0]} isAnimationActive={false} minPointSize={2}>
              {rows.map((r) => (
                <Cell key={r.severity} fill={r.count ? c.severity[r.severity] : c.grid} />
              ))}
              <LabelList dataKey="count" position="right" fill={c.text} fontSize={12} fontWeight={600} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <table className="sr-only-table">
        <caption>Open findings by severity, {total} total</caption>
        <tbody>
          {rows.map((r) => (
            <tr key={r.severity}>
              <th scope="row">{r.label}</th>
              <td>{r.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
