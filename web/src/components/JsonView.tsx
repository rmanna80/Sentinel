import { ActionIcon, CopyButton, Tooltip } from "@mantine/core";
import { IconCheck, IconCopy } from "@tabler/icons-react";
import { useMemo } from "react";
import classes from "./JsonView.module.css";

/** Read-only pretty JSON. Rendered as text (never as HTML), so evidence content can't inject markup. */
export function JsonView({ value, maxHeight = 360 }: { value: unknown; maxHeight?: number }) {
  const text = useMemo(() => {
    try {
      return JSON.stringify(value, null, 2) ?? "null";
    } catch {
      return String(value);
    }
  }, [value]);
  return (
    <div className={classes.wrap}>
      <CopyButton value={text}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? "Copied" : "Copy JSON"}>
            <ActionIcon
              className={classes.copy}
              variant="default"
              size="sm"
              onClick={copy}
              aria-label={copied ? "Copied" : "Copy JSON"}
            >
              {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
            </ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
      <pre className={classes.pre} style={{ maxHeight }} tabIndex={0}>
        {text}
      </pre>
    </div>
  );
}
