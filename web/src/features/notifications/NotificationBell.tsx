import { ActionIcon, Button, Group, Indicator, Popover, ScrollArea, Text, Tooltip, UnstyledButton } from "@mantine/core";
import { IconBell } from "@tabler/icons-react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { Loading } from "../../components/Page";
import { SeverityGlyph } from "../../components/Severity";
import { formatRelative } from "../../lib/format";
import { asSeverity, SEVERITY_LABEL } from "../../lib/severity";
import { useMarkAllRead, useMarkRead, useNotificationList, useUnreadCount } from "./api";
import classes from "./NotificationBell.module.css";

export function NotificationBell() {
  const unread = useUnreadCount();
  const [opened, setOpened] = useState(false);
  const list = useNotificationList(opened);
  const markRead = useMarkRead();
  const markAll = useMarkAllRead();
  const navigate = useNavigate();

  // Hidden while the server module is absent (404) or the count can't be read.
  if (!unread.data) return null;
  const count = unread.data.unread;
  const label = count ? `Notifications, ${count} unread` : "Notifications, none unread";

  return (
    <Popover opened={opened} onChange={setOpened} position="bottom-end" width={380} shadow="md" withinPortal>
      <Popover.Target>
        <Tooltip label={label} disabled={opened}>
          <Indicator
            label={count > 99 ? "99+" : count}
            size={16}
            disabled={count === 0}
            color="red"
            offset={4}
            classNames={{ indicator: classes.count }}
          >
            <ActionIcon variant="subtle" color="gray" size="lg" aria-label={label} onClick={() => setOpened((o) => !o)}>
              <IconBell size={19} stroke={1.8} />
            </ActionIcon>
          </Indicator>
        </Tooltip>
      </Popover.Target>
      <Popover.Dropdown p={0}>
        <Group justify="space-between" px="md" py="sm" className={classes.head}>
          <Text fw={650} size="sm">
            Notifications
          </Text>
          <Button
            size="compact-xs"
            variant="subtle"
            disabled={count === 0}
            loading={markAll.isPending}
            onClick={() => markAll.mutate()}
          >
            Mark all read
          </Button>
        </Group>
        <ScrollArea.Autosize mah={420}>
          {list.isPending ? <Loading /> : null}
          {list.data && list.data.length === 0 ? (
            <Text size="sm" c="dimmed" p="md">
              Nothing yet. New findings at or above your notification threshold show up here.
            </Text>
          ) : null}
          <ul className={classes.list}>
            {list.data?.map((n) => {
              const sev = asSeverity(n.severity);
              return (
                <li key={n.id}>
                  <UnstyledButton
                    className={classes.item}
                    data-unread={n.read_at ? undefined : true}
                    onClick={() => {
                      if (!n.read_at) markRead.mutate(n.id);
                      setOpened(false);
                      if (n.link) navigate(n.link);
                    }}
                  >
                    {sev ? <SeverityGlyph severity={sev} /> : <span className={classes.noSev} />}
                    <span className={classes.itemText}>
                      <span className={classes.itemTitle}>{n.title}</span>
                      <span className={classes.itemMeta}>
                        {sev ? SEVERITY_LABEL[sev] : n.severity}, {formatRelative(n.created_at)}
                        {n.read_at ? "" : ", unread"}
                      </span>
                    </span>
                  </UnstyledButton>
                </li>
              );
            })}
          </ul>
        </ScrollArea.Autosize>
      </Popover.Dropdown>
    </Popover>
  );
}
