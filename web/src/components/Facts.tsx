import type { ReactNode } from "react";
import classes from "./Facts.module.css";

/** Label/value pairs in a definition list. */
export function Facts({ items, columns = 1 }: { items: [ReactNode, ReactNode][]; columns?: 1 | 2 | 3 }) {
  return (
    <dl className={classes.list} data-cols={columns}>
      {items.map(([label, value], i) => (
        <div key={i} className={classes.row}>
          <dt className={classes.label}>{label}</dt>
          <dd className={classes.value}>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
