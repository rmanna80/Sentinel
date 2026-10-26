/**
 * Finding status workflow. "resolved" is never offered to a person: only a passing re-run of the check
 * (Verify) can resolve a finding. The server enforces this too; the UI filters defensively in case the
 * server's allowed list ever includes it.
 */
export const STATUS_LABEL: Record<string, string> = {
  new: "New",
  confirmed: "Confirmed",
  in_progress: "In progress",
  accepted_risk: "Accepted risk",
  resolved: "Resolved",
  reopened: "Reopened",
};

export const STATUS_HELP: Record<string, string> = {
  confirmed: "You've checked it and it's real.",
  in_progress: "Someone is fixing it.",
  accepted_risk: "You've decided to live with it. It stays open but doesn't count as unresolved.",
};

export function statusChoices(allowed: readonly string[]): { value: string; label: string; description?: string }[] {
  return allowed
    .filter((s) => s !== "resolved")
    .map((s) => ({ value: s, label: STATUS_LABEL[s] ?? s, description: STATUS_HELP[s] }));
}

export const FINDING_KIND: Record<string, { label: string; help: string }> = {
  verified: { label: "Verified", help: "Directly observed on the device, for example a setting reported as off." },
  heuristic: { label: "Heuristic", help: "Suspicious, not proof of a problem. Check it before acting." },
  informational: { label: "Informational", help: "Context only. Never lowers the score." },
};

export const CONFIDENCE_LABEL: Record<string, string> = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
};
