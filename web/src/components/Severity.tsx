import { Tooltip } from "@mantine/core";
import { asSeverity, SEVERITY_LABEL, SEVERITY_LEVEL, type Severity } from "../lib/severity";
import classes from "./Severity.module.css";

/** Four ascending steps; the filled count is the severity level. Shape carries the order, not hue alone. */
export function SeverityGlyph({ severity, size = 12 }: { severity: Severity; size?: number }) {
  const level = SEVERITY_LEVEL[severity];
  return (
    <svg
      className={classes.glyph}
      data-sev={severity}
      width={size}
      height={size}
      viewBox="0 0 12 12"
      aria-hidden="true"
      focusable="false"
    >
      {[0, 1, 2, 3].map((i) => (
        <rect
          key={i}
          x={i * 3}
          y={9 - i * 3}
          width={2}
          height={3 + i * 3}
          rx={0.6}
          className={i < level ? classes.on : classes.off}
        />
      ))}
    </svg>
  );
}

export interface SeverityBadgeProps {
  severity: string | null | undefined;
  /** "tag" is the bordered chip; "inline" is glyph plus word for dense rows. */
  variant?: "tag" | "inline";
  size?: "sm" | "md";
}

export function SeverityBadge({ severity, variant = "tag", size = "sm" }: SeverityBadgeProps) {
  const sev = asSeverity(severity);
  if (!sev) {
    return (
      <span className={classes.badge} data-variant={variant} data-size={size} data-sev="unknown">
        {severity ? `Severity: ${severity}` : "Severity unknown"}
      </span>
    );
  }
  return (
    <span className={classes.badge} data-variant={variant} data-size={size} data-sev={sev}>
      <SeverityGlyph severity={sev} size={size === "md" ? 14 : 12} />
      <span>{SEVERITY_LABEL[sev]}</span>
    </span>
  );
}

export function KevBadge() {
  return (
    <Tooltip label="Listed in CISA's Known Exploited Vulnerabilities catalog: attackers are using this in the wild.">
      <span className={classes.kev} tabIndex={0}>
        Known exploited
      </span>
    </Tooltip>
  );
}
