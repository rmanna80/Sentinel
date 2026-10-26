import { Tooltip } from "@mantine/core";
import { Fragment } from "react";
import { Link } from "react-router";
import { citationHref, parseCitations, type CitationRef } from "./citations";
import classes from "./Assistant.module.css";

export interface CitationCheck {
  type: string;
  id: string | number;
  valid: boolean;
}

const LABEL: Record<string, string> = { finding: "Finding", alert: "Alert", scan: "Scan", event: "Event", vuln: "Vulnerability" };

/**
 * Renders model or rule-built text as plain text (React escapes it), turning citations into links.
 * A citation the server could not find in the database is shown as unverified and is not linked.
 */
export function CitedText({ text, checks }: { text: string; checks?: CitationCheck[] }) {
  const invalid = new Set((checks ?? []).filter((c) => !c.valid).map((c) => `${c.type}:${c.id}`));
  const segments = parseCitations(text);
  return (
    <div className={classes.cited}>
      {segments.map((s, i) =>
        s.kind === "text" ? (
          <Fragment key={i}>{s.text}</Fragment>
        ) : (
          <span key={i} className={classes.citeGroup}>
            {s.refs.map((r) => (
              <CitationChip key={`${r.type}:${r.id}`} r={r} unverified={invalid.has(`${r.type}:${r.id}`)} />
            ))}
          </span>
        ),
      )}
    </div>
  );
}

function CitationChip({ r, unverified }: { r: CitationRef; unverified: boolean }) {
  const label = `${LABEL[r.type] ?? r.type} ${r.id}`;
  const href = citationHref(r);
  if (unverified || !href) {
    return (
      <Tooltip label={unverified ? "Not found in Sentinel's database. Treat this claim with care." : "No page for this reference"}>
        <span className={classes.chip} data-unverified={unverified || undefined} tabIndex={0}>
          {label}
          {unverified ? " (unverified)" : ""}
        </span>
      </Tooltip>
    );
  }
  return (
    <Link to={href} className={classes.chip}>
      {label}
    </Link>
  );
}
