import { Tooltip } from "@mantine/core";
import { formatDateTime, formatRelative, formatShort, parseDate, utcLabel } from "../lib/format";

/** A timestamp in local time with a relative hint; hover shows the full local and UTC time. */
export function Time({
  value,
  mode = "both",
  empty = "Never",
}: {
  value: string | null | undefined;
  mode?: "both" | "relative" | "absolute";
  empty?: string;
}) {
  const d = parseDate(value);
  if (!d) return <span className="sn-dim">{empty}</span>;
  const iso = d.toISOString();
  const rel = formatRelative(iso);
  const label = mode === "relative" ? rel : mode === "absolute" ? formatShort(iso) : `${formatShort(iso)}`;
  return (
    <Tooltip label={`${formatDateTime(iso)} your time, ${utcLabel(iso)}`}>
      <time dateTime={iso} className="sn-num" tabIndex={0}>
        <span style={{ whiteSpace: "nowrap" }}>{label}</span>
        {mode === "both" ? (
          <>
            {" "}
            <span className="sn-dim" style={{ whiteSpace: "nowrap" }}>
              ({rel})
            </span>
          </>
        ) : null}
      </time>
    </Tooltip>
  );
}
