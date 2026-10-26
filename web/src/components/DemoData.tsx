import { Tooltip } from "@mantine/core";
import { IconFlask } from "@tabler/icons-react";
import type { ReactNode } from "react";
import classes from "./DemoData.module.css";

export const DEMO_EXPLANATION =
  "Fixture data: these results came from a recorded sample, not from scanning a real device. Use them to learn the dashboard; don't act on them.";

export function isFixture(dataMode: string | null | undefined): boolean {
  return dataMode === "fixture";
}

/** Small marker for a row or a card whose numbers came from fixture data. */
export function DemoBadge({ compact = false }: { compact?: boolean }) {
  return (
    <Tooltip label={DEMO_EXPLANATION}>
      <span className={classes.badge} tabIndex={0} data-compact={compact || undefined}>
        <IconFlask size={13} stroke={2} aria-hidden="true" />
        Demo data
      </span>
    </Tooltip>
  );
}

/** Full-width notice above any view that includes fixture data. */
export function DemoBanner({ children }: { children?: ReactNode }) {
  return (
    <div className={classes.banner} role="note">
      <IconFlask size={18} stroke={1.8} aria-hidden="true" className={classes.bannerIcon} />
      <div>
        <strong>Demo data on this page.</strong>{" "}
        <span>{children ?? DEMO_EXPLANATION}</span>
      </div>
    </div>
  );
}
