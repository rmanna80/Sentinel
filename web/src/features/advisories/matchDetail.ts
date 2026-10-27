/** match_detail is an open object on the wire; read the three known lists of strings out of it safely. */
function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((x): x is string => typeof x === "string") : [];
}

export interface MatchChips {
  software: string[];
  kevCves: string[];
  findingCves: string[];
}

export function matchChips(detail: Record<string, unknown> | null | undefined): MatchChips {
  const d = detail ?? {};
  return {
    software: stringList(d.software),
    kevCves: stringList(d.kev_cves),
    findingCves: stringList(d.finding_cves),
  };
}
