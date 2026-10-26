export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Ordinal level drawn by the severity glyph: four steps, so severity never depends on color alone. */
export const SEVERITY_LEVEL: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function asSeverity(value: string | null | undefined): Severity | null {
  if (!value) return null;
  const v = value.toLowerCase();
  if (v === "informational") return "info";
  return (SEVERITIES as readonly string[]).includes(v) ? (v as Severity) : null;
}

/** Threat level uses "informational" where findings use "info". */
export function threatLabel(level: string): string {
  const sev = asSeverity(level);
  if (sev === "info") return "Informational";
  return sev ? SEVERITY_LABEL[sev] : level;
}

/** Chart colors (CSS variables carry the same values for HTML). Checked for >= 3:1 on every surface. */
export const SEVERITY_COLORS: Record<"light" | "dark", Record<Severity, string>> = {
  dark: { critical: "#F4646A", high: "#F08E52", medium: "#E2B84A", low: "#54B9D0", info: "#8F9C98" },
  light: { critical: "#C8323C", high: "#B8541C", medium: "#8F6B00", low: "#1C7A90", info: "#66716E" },
};
