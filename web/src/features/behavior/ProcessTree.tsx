import { Text } from "@mantine/core";
import { basename, processAncestry } from "./evidence";
import classes from "./Behavior.module.css";

/** The acting process and its ancestors, nearest first, as the server sends them. */
export function ProcessTree({ tree }: { tree: ReadonlyArray<Record<string, unknown>> | null | undefined }) {
  const nodes = processAncestry(tree);
  if (!nodes.length) {
    return (
      <Text size="sm" c="dimmed">
        No process context was captured for this detection.
      </Text>
    );
  }
  return (
    <ol className={classes.tree}>
      {nodes.map((node, i) => (
        <li key={node.processGuid ?? i}>
          {i > 0 ? (
            <div className={classes.treeArrow} aria-hidden="true">
              ↑ launched by
            </div>
          ) : null}
          <div className={classes.proc} data-primary={i === 0 ? "yes" : undefined}>
            <div className={classes.procHead}>
              <span className={classes.procImage}>{basename(node.image) || "(unknown process)"}</span>
              {node.pid !== null ? <span className={classes.procPid}>pid {node.pid}</span> : null}
              {node.user ? (
                <Text component="span" size="xs" c="dimmed">
                  {node.user}
                </Text>
              ) : null}
            </div>
            {node.image && basename(node.image) !== node.image ? (
              <div className={classes.procCmd}>{node.image}</div>
            ) : null}
            {node.commandLine ? <div className={classes.procCmd}>{node.commandLine}</div> : null}
          </div>
        </li>
      ))}
    </ol>
  );
}
