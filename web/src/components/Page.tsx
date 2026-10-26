import { Alert, Button, Group, Loader, Stack, Text, Title } from "@mantine/core";
import { useDocumentTitle } from "@mantine/hooks";
import { IconAlertCircle, IconRefresh } from "@tabler/icons-react";
import type { ReactNode } from "react";
import { errorMessage } from "../api/client";
import classes from "./Page.module.css";

export function PageHeader({
  title,
  description,
  actions,
  meta,
  docTitle,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
  docTitle?: string;
}) {
  useDocumentTitle(`${docTitle ?? (typeof title === "string" ? title : "Sentinel")} | Sentinel`);
  return (
    <header className={classes.header}>
      <div className={classes.headText}>
        <Title order={1} className={classes.title}>
          {title}
        </Title>
        {description ? <Text className={classes.description}>{description}</Text> : null}
        {meta ? <div className={classes.meta}>{meta}</div> : null}
      </div>
      {actions ? <Group gap="xs" className={classes.actions}>{actions}</Group> : null}
    </header>
  );
}

/** A bordered region. Panels are flat (no shadow); hierarchy comes from the header and spacing. */
export function Panel({
  title,
  description,
  actions,
  children,
  padded = true,
  className,
  id,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  padded?: boolean;
  className?: string;
  id?: string;
}) {
  const headingId = id ? `${id}-title` : undefined;
  return (
    <section className={`${classes.panel} ${className ?? ""}`} aria-labelledby={headingId} id={id}>
      {title || actions ? (
        <div className={classes.panelHead}>
          <div>
            {title ? (
              <Title order={2} className={classes.panelTitle} id={headingId}>
                {title}
              </Title>
            ) : null}
            {description ? <Text className={classes.panelDesc}>{description}</Text> : null}
          </div>
          {actions ? <Group gap={6} wrap="nowrap">{actions}</Group> : null}
        </div>
      ) : null}
      <div className={padded ? classes.panelBody : undefined}>{children}</div>
    </section>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <Group gap="xs" p="md" c="dimmed" role="status" aria-live="polite">
      <Loader size="xs" />
      <Text size="sm">{label}…</Text>
    </Group>
  );
}

export function ErrorState({ error, onRetry, title }: { error: unknown; onRetry?: () => void; title?: string }) {
  return (
    <Alert
      color="red"
      variant="light"
      icon={<IconAlertCircle size={18} />}
      title={title ?? "Couldn't load this"}
      role="alert"
    >
      <Stack gap="xs" align="flex-start">
        <Text size="sm">{errorMessage(error)}</Text>
        {onRetry ? (
          <Button size="xs" variant="default" leftSection={<IconRefresh size={14} />} onClick={onRetry}>
            Try again
          </Button>
        ) : null}
      </Stack>
    </Alert>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className={classes.empty}>
      <Text fw={650} size="md">
        {title}
      </Text>
      {children ? (
        <Text size="sm" c="dimmed" maw={520}>
          {children}
        </Text>
      ) : null}
      {action ? <div>{action}</div> : null}
    </div>
  );
}
