import classes from "./Meter.module.css";

/** A 0–100% meter whose fill steps up at 80% and 90%. The number is always shown beside it. */
export function Meter({ label, value }: { label: string; value: number | null | undefined }) {
  const known = typeof value === "number" && Number.isFinite(value);
  const pct = known ? Math.max(0, Math.min(100, value)) : 0;
  const level = !known ? "none" : pct >= 90 ? "high" : pct >= 80 ? "warn" : "ok";
  return (
    <div className={classes.row}>
      <span className={classes.label}>{label}</span>
      <div
        className={classes.track}
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={known ? Math.round(pct) : undefined}
        aria-valuetext={known ? `${pct.toFixed(0)}%` : "No data"}
        data-level={level}
      >
        <div className={classes.fill} style={{ width: `${pct}%` }} />
      </div>
      <span className={classes.value} data-level={level}>
        {known ? `${pct.toFixed(0)}%` : "No data"}
      </span>
    </div>
  );
}
