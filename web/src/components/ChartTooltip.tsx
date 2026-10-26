import type { ReactNode } from "react";
import classes from "./ChartTooltip.module.css";

export interface TooltipRow {
  key: string;
  color: string;
  label: ReactNode;
  value: ReactNode;
  dashed?: boolean;
}

/** HTML tooltip body for Recharts: text uses text tokens; a colored key beside it carries identity. */
export function ChartTooltipBody({ title, rows, footer }: { title: ReactNode; rows: TooltipRow[]; footer?: ReactNode }) {
  return (
    <div className={classes.box}>
      <div className={classes.title}>{title}</div>
      {rows.map((r) => (
        <div key={r.key} className={classes.row}>
          <span className={classes.key} data-dashed={r.dashed || undefined} style={{ borderColor: r.color }} />
          <span className={classes.label}>{r.label}</span>
          <span className={classes.value}>{r.value}</span>
        </div>
      ))}
      {footer ? <div className={classes.footer}>{footer}</div> : null}
    </div>
  );
}

export function LegendKey({ color, label, dashed }: { color: string; label: ReactNode; dashed?: boolean }) {
  return (
    <span className={classes.legendItem}>
      <span className={classes.key} data-dashed={dashed || undefined} style={{ borderColor: color }} />
      {label}
    </span>
  );
}
