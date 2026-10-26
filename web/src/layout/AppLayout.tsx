import {
  ActionIcon,
  AppShell,
  Avatar,
  Burger,
  Group,
  Menu,
  ScrollArea,
  Select,
  Text,
  Tooltip,
  UnstyledButton,
  useComputedColorScheme,
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconChevronDown, IconDevices, IconLogout, IconMoon, IconSun, IconUserCircle } from "@tabler/icons-react";
import { Suspense, useEffect } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { useAuth } from "../auth/AuthContext";
import { Loading } from "../components/Page";
import { useDevices } from "../features/devices/api";
import { NotificationBell } from "../features/notifications/NotificationBell";
import { useDeviceScope } from "./DeviceScope";
import classes from "./AppLayout.module.css";
import { ModeBadge } from "./ModeBadge";
import { NAV } from "./nav";

function Brand() {
  return (
    <div className={classes.brand}>
      <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
        <rect x="3" y="3" width="26" height="26" rx="7" fill="none" stroke="currentColor" strokeWidth="2.6" />
        <rect x="8.5" y="14" width="15" height="4" rx="2" fill="currentColor" />
      </svg>
      <span>Sentinel</span>
    </div>
  );
}

function Navigation({ onNavigate }: { onNavigate: () => void }) {
  return (
    <nav aria-label="Sections" className={classes.nav}>
      {NAV.map((group) => (
        <div key={group.label} className={classes.group}>
          <div className={classes.groupLabel} id={`nav-${group.label}`}>
            {group.label}
          </div>
          <ul aria-labelledby={`nav-${group.label}`}>
            {group.items.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.to === "/"}
                  className={({ isActive }) => `${classes.link} ${isActive ? classes.active : ""}`}
                  onClick={onNavigate}
                >
                  <item.icon size={18} stroke={1.7} aria-hidden="true" className={classes.linkIcon} />
                  <span className={classes.linkLabel}>{item.label}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function DeviceSelector() {
  const { deviceId, setDeviceId } = useDeviceScope();
  const devices = useDevices();
  const list = devices.data ?? [];

  // A remembered device that was revoked or removed falls back to "All devices".
  useEffect(() => {
    if (deviceId !== null && devices.data && !devices.data.some((d) => d.id === deviceId)) setDeviceId(null);
  }, [deviceId, devices.data, setDeviceId]);

  return (
    <Select
      aria-label="Device scope"
      className={classes.deviceSelect}
      size="sm"
      leftSection={<IconDevices size={16} stroke={1.7} />}
      data={[
        { value: "all", label: "All devices" },
        ...list.map((d) => ({ value: String(d.id), label: `${d.name}${d.online ? "" : " (offline)"}` })),
      ]}
      value={deviceId === null ? "all" : String(deviceId)}
      onChange={(v) => setDeviceId(!v || v === "all" ? null : Number(v))}
      searchable={list.length > 8}
      comboboxProps={{ width: 260, position: "bottom-start" }}
    />
  );
}

function ThemeToggle() {
  const { setColorScheme } = useMantineColorScheme();
  const computed = useComputedColorScheme("dark");
  const next = computed === "dark" ? "light" : "dark";
  const label = `Switch to ${next} theme`;
  return (
    <Tooltip label={label}>
      <ActionIcon variant="subtle" color="gray" size="lg" aria-label={label} onClick={() => setColorScheme(next)}>
        {computed === "dark" ? <IconSun size={19} stroke={1.8} /> : <IconMoon size={19} stroke={1.8} />}
      </ActionIcon>
    </Tooltip>
  );
}

function UserMenu() {
  const { state, signOut } = useAuth();
  const navigate = useNavigate();
  const name = state.username ?? "Account";
  return (
    <Menu position="bottom-end" width={220} shadow="md">
      <Menu.Target>
        <UnstyledButton className={classes.user} aria-label={`Account menu for ${name}`}>
          <Avatar size={26} radius="xl" color="iris" variant="light">
            {name.slice(0, 1).toUpperCase()}
          </Avatar>
          <Text size="sm" fw={600} visibleFrom="md" className={classes.userName}>
            {name}
          </Text>
          <IconChevronDown size={14} aria-hidden="true" />
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Signed in as {name}</Menu.Label>
        <Menu.Item leftSection={<IconUserCircle size={16} />} onClick={() => navigate("/settings?tab=account")}>
          Account and password
        </Menu.Item>
        <Menu.Divider />
        <Menu.Item leftSection={<IconLogout size={16} />} onClick={() => void signOut()}>
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure(false);
  const { state } = useAuth();
  const location = useLocation();

  // Move focus to the main region after navigation so keyboard and screen reader users land on the new page.
  useEffect(() => {
    const main = document.getElementById("main");
    main?.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <AppShell
      header={{ height: 54 }}
      navbar={{ width: 236, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding={0}
      layout="alt"
      classNames={{ header: classes.header, navbar: classes.navbar, main: classes.main }}
    >
      <a href="#main" className={classes.skip}>
        Skip to content
      </a>
      <AppShell.Header>
        <Group h="100%" px="md" gap="sm" wrap="nowrap" justify="space-between">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" aria-label="Toggle navigation" />
            <div className={classes.headerBrand}>
              <Brand />
            </div>
            <DeviceSelector />
          </Group>
          <Group gap={6} wrap="nowrap">
            <ModeBadge mode={state.mode} />
            <NotificationBell />
            <ThemeToggle />
            <UserMenu />
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar>
        <AppShell.Section className={classes.navBrand} visibleFrom="sm">
          <Brand />
        </AppShell.Section>
        <AppShell.Section grow component={ScrollArea} type="scroll">
          <Navigation onNavigate={close} />
        </AppShell.Section>
        <AppShell.Section className={classes.navFoot}>
          <Text size="xs" c="dimmed">
            Local only: this dashboard talks to the server on this computer.
          </Text>
        </AppShell.Section>
      </AppShell.Navbar>
      <AppShell.Main>
        <main id="main" tabIndex={-1} className={classes.content}>
          <Suspense fallback={<Loading />}>
            <Outlet />
          </Suspense>
        </main>
      </AppShell.Main>
    </AppShell>
  );
}
