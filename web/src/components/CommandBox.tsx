import { ActionIcon, CopyButton, Tooltip } from "@mantine/core";
import { IconCheck, IconCopy } from "@tabler/icons-react";
import classes from "./CommandBox.module.css";

/** A command to paste into a terminal, with a copy button. */
export function CommandBox({ command, label }: { command: string; label?: string }) {
  return (
    <div className={classes.box}>
      {label ? <span className={classes.prompt}>{label}</span> : null}
      <code className={classes.code} data-testid="command-text">
        {command}
      </code>
      <CopyButton value={command}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? "Copied" : "Copy command"}>
            <ActionIcon variant="subtle" color="gray" onClick={copy} aria-label={copied ? "Copied" : "Copy command"}>
              {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
            </ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </div>
  );
}
