import type { FieldSummary } from "../../api/types";
import classes from "./Field.module.css";

function Tile({ label, value, note, highlight }: { label: string; value: number; note?: string; highlight?: "warn" | "danger" }) {
  return (
    <div className={classes.tile} data-highlight={value > 0 ? highlight : undefined}>
      <div className={classes.tileLabel}>{label}</div>
      <div className={classes.tileValue}>{value}</div>
      {note ? <div className={classes.tileNote}>{note}</div> : null}
    </div>
  );
}

/** Four summary tiles. Rogue suspects and your own weak networks turn red/amber when above zero. */
export function FieldSummaryTiles({ summary }: { summary: FieldSummary }) {
  return (
    <div className={classes.tiles}>
      <Tile label="Captures" value={summary.captures} note="Surveys you've uploaded" />
      <Tile label="Access points seen" value={summary.access_points} note="Across all captures" />
      <Tile label="Rogue suspects" value={summary.rogue_suspects} note="Impersonating your SSIDs" highlight="danger" />
      <Tile label="Your weak networks" value={summary.weak_own} note="Open or weak encryption" highlight="warn" />
    </div>
  );
}
