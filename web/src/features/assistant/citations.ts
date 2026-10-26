/**
 * Assistant answers are plain text with citations like [finding:12], [finding:12, 13] or [finding:12; scan:4].
 * This splits text into plain-text and citation segments so the UI can render links without ever treating the
 * answer as HTML.
 */
export const CITATION_TYPES = ["finding", "alert", "scan", "event", "vuln"] as const;
export type CitationType = (typeof CITATION_TYPES)[number];

export interface CitationRef {
  type: CitationType;
  id: string;
}

export type Segment = { kind: "text"; text: string } | { kind: "cite"; raw: string; refs: CitationRef[] };

const BLOCK = /\[\s*((?:finding|alert|scan|event|vuln)\s*:[^[\]\n]{1,300})\]/gi;

function parseBlock(inner: string): CitationRef[] {
  const refs: CitationRef[] = [];
  let current: CitationType | null = null;
  for (const partRaw of inner.split(/[,;]/)) {
    const part = partRaw.trim();
    if (!part) continue;
    const idx = part.indexOf(":");
    let id = part;
    if (idx >= 0) {
      const kind = part.slice(0, idx).trim().toLowerCase();
      if ((CITATION_TYPES as readonly string[]).includes(kind)) {
        current = kind as CitationType;
        id = part.slice(idx + 1).trim();
      }
    }
    if (current && id) refs.push({ type: current, id });
  }
  return refs;
}

export function parseCitations(text: string): Segment[] {
  const out: Segment[] = [];
  let last = 0;
  for (const m of text.matchAll(BLOCK)) {
    const start = m.index ?? 0;
    if (start > last) out.push({ kind: "text", text: text.slice(last, start) });
    const refs = parseBlock(m[1]);
    if (refs.length) out.push({ kind: "cite", raw: m[0], refs });
    else out.push({ kind: "text", text: m[0] });
    last = start + m[0].length;
  }
  if (last < text.length) out.push({ kind: "text", text: text.slice(last) });
  return out;
}

/** Where a citation points inside the dashboard. Numeric ids only for numeric types. */
export function citationHref(ref: CitationRef): string | null {
  const numeric = /^\d+$/.test(ref.id);
  switch (ref.type) {
    case "finding":
      return numeric ? `/vulnerabilities/${ref.id}` : null;
    case "alert":
      return numeric ? `/threats/alerts/${ref.id}` : null;
    case "scan":
      return numeric ? `/scans/${ref.id}` : null;
    case "event":
      return numeric ? `/logs?event=${ref.id}` : null;
    case "vuln":
      return `/vulnerabilities?status=all&source=vuln_matcher&q=${encodeURIComponent(ref.id)}`;
  }
}
