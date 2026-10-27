import { Anchor, type AnchorProps } from "@mantine/core";
import { IconExternalLink } from "@tabler/icons-react";
import type { ReactNode } from "react";
import { isHttpUrl } from "../lib/url";

/**
 * Renders an anchor only when `url` is a plain http(s) link; anything else (javascript:, data:, empty)
 * falls back to plain text, so an unsafe scheme is never put in an href. Opens in a new tab safely.
 */
export function ExternalLink({
  url,
  children,
  size,
  fw,
}: {
  url: string | null | undefined;
  children?: ReactNode;
  size?: AnchorProps["size"];
  fw?: AnchorProps["fw"];
}) {
  const label = children ?? url ?? "";
  if (!isHttpUrl(url)) {
    return <span>{label}</span>;
  }
  return (
    <Anchor href={url} target="_blank" rel="noopener noreferrer" size={size} fw={fw}>
      {label} <IconExternalLink size={13} aria-label="(opens in a new tab)" style={{ verticalAlign: "-1px" }} />
    </Anchor>
  );
}
