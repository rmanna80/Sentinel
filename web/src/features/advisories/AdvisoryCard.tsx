import { Tooltip } from "@mantine/core";
import type { AdvisoryOut } from "../../api/types";
import { ExternalLink } from "../../components/ExternalLink";
import { SeverityBadge } from "../../components/Severity";
import { Tag } from "../../components/Status";
import { Time } from "../../components/Time";
import classes from "./Advisories.module.css";
import { matchChips } from "./matchDetail";

function asDate(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** One advisory in the list: severity chip, an external title link, tags, CVEs and any match chips. */
export function AdvisoryCard({ advisory, onOpen }: { advisory: AdvisoryOut; onOpen: () => void }) {
  const chips = matchChips(advisory.match_detail);
  return (
    <div className={classes.card}>
      <div className={classes.cardHead}>
        <SeverityBadge severity={advisory.severity_hint} />
        <span className={classes.title}>
          <ExternalLink url={advisory.url}>{advisory.title}</ExternalLink>
        </span>
        {advisory.matched ? (
          <Tooltip label="Matched against your software inventory, KEV list or open findings.">
            <span tabIndex={0}>
              <Tag tone="accent">Matched to you</Tag>
            </span>
          </Tooltip>
        ) : null}
        {advisory.status === "pinned" ? <Tag tone="warn">Pinned</Tag> : null}
        {advisory.status === "dismissed" ? <Tag tone="neutral">Dismissed</Tag> : null}
      </div>
      <button type="button" className={classes.body} onClick={onOpen} aria-label={`Open advisory: ${advisory.title}`}>
        {advisory.summary ? <div className={classes.summary}>{advisory.summary}</div> : null}
        <div className={classes.chips}>
          {advisory.tags.map((t) => (
            <Tag key={`tag-${t}`}>{t}</Tag>
          ))}
          {advisory.cve_ids.map((c) => (
            <span key={`cve-${c}`} className={classes.cve}>
              {c}
            </span>
          ))}
          {chips.software.map((s) => (
            <Tag key={`sw-${s}`} tone="accent" title="Software in your inventory named in this advisory">
              {s}
            </Tag>
          ))}
          {chips.kevCves.map((c) => (
            <Tag key={`kev-${c}`} tone="danger" title="Also on CISA's Known Exploited Vulnerabilities list">
              KEV {c}
            </Tag>
          ))}
          {chips.findingCves.map((c) => (
            <Tag key={`fc-${c}`} tone="warn" title="Matches an open finding on your devices">
              Finding {c}
            </Tag>
          ))}
        </div>
        <div className={classes.foot}>
          <span>{advisory.source}</span>
          {advisory.author ? <span>by {advisory.author}</span> : null}
          <Time value={asDate(advisory.published_at)} mode="relative" empty="Undated" />
          <span aria-hidden="true">· View details</span>
        </div>
      </button>
    </div>
  );
}
