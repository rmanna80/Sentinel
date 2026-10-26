import { Collapse, Text, UnstyledButton } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconChevronDown } from "@tabler/icons-react";
import { useId } from "react";
import { formatPercent } from "../../lib/format";
import { threatLabel, asSeverity } from "../../lib/severity";
import { SeverityGlyph } from "../../components/Severity";
import classes from "./ScoreCard.module.css";

export interface ScoreCardProps {
  score: number | null;
  rawScore: number;
  coverage: number | null;
  checksCompleted: number;
  checksApplicable: number;
  threatLevel: string;
  scoreBasis: string;
  /** Fraction of applicable checks that must complete before a score is shown (server default 0.75). */
  minCoverage?: number;
}

/**
 * The security score, or "Incomplete" when too few checks completed. Never shows a stand-in number:
 * when the score is null the card says why and how many checks ran.
 */
export function ScoreCard(props: ScoreCardProps) {
  const { score, coverage, checksCompleted, checksApplicable, threatLevel, scoreBasis } = props;
  const minCoverage = props.minCoverage ?? parseMinCoverage(scoreBasis) ?? 0.75;
  const [open, { toggle }] = useDisclosure(false);
  const basisId = useId();
  const incomplete = score === null;
  const covPct = coverage === null ? 0 : Math.max(0, Math.min(1, coverage)) * 100;
  const threat = asSeverity(threatLevel);

  let reason: string;
  if (checksApplicable === 0) {
    reason = "No posture scan has finished yet, so there is nothing to score. Run a full or posture scan.";
  } else if (incomplete) {
    reason = `Only ${checksCompleted} of ${checksApplicable} applicable checks completed (${formatPercent(coverage)}). A score needs at least ${formatPercent(minCoverage)}.`;
  } else {
    reason = `${checksCompleted} of ${checksApplicable} applicable checks completed.`;
  }

  return (
    <section className={classes.card} data-state={incomplete ? "incomplete" : "scored"} aria-labelledby={`${basisId}-h`}>
      <div className={classes.top}>
        <h2 className={classes.heading} id={`${basisId}-h`}>
          Security score
        </h2>
        <span className={classes.threat}>
          {threat ? <SeverityGlyph severity={threat} /> : null}
          <span>
            Threat level <strong>{threatLabel(threatLevel)}</strong>
          </span>
        </span>
      </div>

      <div className={classes.figure} data-testid="score-value">
        {incomplete ? (
          <span className={classes.incomplete}>Incomplete</span>
        ) : (
          <>
            <span className={classes.number}>{score}</span>
            <span className={classes.outOf}>/ 100</span>
          </>
        )}
      </div>
      <Text className={classes.reason}>{reason}</Text>

      <div className={classes.coverage}>
        <div className={classes.coverageLabel}>
          <span>Check coverage</span>
          <span className="sn-num">
            {checksCompleted} / {checksApplicable} checks
          </span>
        </div>
        <div
          className={classes.track}
          role="meter"
          aria-label="Check coverage"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={coverage === null ? undefined : Math.round(covPct)}
          aria-valuetext={
            coverage === null
              ? "No checks have run"
              : `${formatPercent(coverage)} of applicable checks completed; ${formatPercent(minCoverage)} needed for a score`
          }
        >
          <div className={classes.fill} style={{ width: `${covPct}%` }} />
          <div className={classes.threshold} style={{ left: `${minCoverage * 100}%` }} aria-hidden="true" />
        </div>
        <div className={classes.thresholdLabel} style={{ paddingLeft: `calc(${minCoverage * 100}% - 40px)` }}>
          {formatPercent(minCoverage)} needed
        </div>
      </div>

      <UnstyledButton
        className={classes.basisToggle}
        onClick={toggle}
        aria-expanded={open}
        aria-controls={basisId}
      >
        How this score is calculated
        <IconChevronDown size={14} className={classes.chev} data-open={open || undefined} aria-hidden="true" />
      </UnstyledButton>
      <Collapse expanded={open} id={basisId}>
        <Text className={classes.basis}>
          {scoreBasis}
          {incomplete && checksApplicable > 0 ? (
            <> The open findings alone would give {props.rawScore}; that number isn't shown as the score because too few checks ran to trust it.</>
          ) : null}
        </Text>
      </Collapse>
    </section>
  );
}

function parseMinCoverage(basis: string): number | null {
  const m = /at least (\d{1,3})%/.exec(basis);
  return m ? Number(m[1]) / 100 : null;
}
