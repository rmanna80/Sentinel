import { Tooltip } from "@mantine/core";
import classes from "./ModeBadge.module.css";

const MODES: Record<string, { label: string; hint: string }> = {
  demo: {
    label: "Demo mode",
    hint: "This server accepts fixture (demo) data. Results marked Demo data did not come from a real device.",
  },
  test: { label: "Test mode", hint: "This server runs in test mode. Data here is for development only." },
};

/** Visible whenever the server is not in production mode. */
export function ModeBadge({ mode }: { mode: string }) {
  const spec = MODES[mode];
  if (!spec) return null;
  return (
    <Tooltip label={spec.hint}>
      <span className={classes.badge} data-mode={mode} tabIndex={0} aria-label={`${spec.label}. ${spec.hint}`}>
        {spec.label}
      </span>
    </Tooltip>
  );
}
