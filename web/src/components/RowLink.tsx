import { Link, type LinkProps } from "react-router";

/** A link styled for use inside table cells (keyboard reachable, accent color). */
export function RowLink(props: LinkProps) {
  return <Link {...props} className={`sn-link ${props.className ?? ""}`} />;
}
