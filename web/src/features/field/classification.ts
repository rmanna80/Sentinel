/** How each observation classification is labelled, toned and ordered (most prominent first). */
export const CLASSIFICATION: Record<string, { label: string; tone: "good" | "warn" | "danger" | "neutral" | "accent"; order: number; prominent?: boolean }> = {
  rogue_suspect: { label: "Rogue suspect", tone: "danger", order: 0, prominent: true },
  weak_own: { label: "Weak (yours)", tone: "warn", order: 1, prominent: true },
  unknown: { label: "Unknown", tone: "neutral", order: 2 },
  known: { label: "Known", tone: "accent", order: 3 },
  own: { label: "Yours", tone: "good", order: 4 },
};

export function classificationOrder(value: string): number {
  return CLASSIFICATION[value]?.order ?? 50;
}
