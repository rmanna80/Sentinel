import {
  IconActivityHeartbeat,
  IconAlertTriangle,
  IconAntenna,
  IconBug,
  IconCalendarTime,
  IconChartBar,
  IconDevices,
  IconLayoutDashboard,
  IconListDetails,
  IconMail,
  IconMessageChatbot,
  IconNetwork,
  IconPlug,
  IconRadar,
  IconRss,
  IconSettings,
  type Icon,
} from "@tabler/icons-react";

export interface NavItem {
  label: string;
  to: string;
  icon: Icon;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: "Posture",
    items: [
      { label: "Overview", to: "/", icon: IconLayoutDashboard },
      { label: "Security scans", to: "/scans", icon: IconRadar },
      { label: "Vulnerabilities", to: "/vulnerabilities", icon: IconBug },
      { label: "Devices", to: "/devices", icon: IconDevices },
      { label: "System diagnostics", to: "/diagnostics", icon: IconActivityHeartbeat },
    ],
  },
  {
    label: "Detection",
    items: [
      { label: "Threat detection", to: "/threats", icon: IconAlertTriangle },
      { label: "Logs and events", to: "/logs", icon: IconListDetails },
      { label: "Advisories", to: "/advisories", icon: IconRss },
      { label: "Network security", to: "/network", icon: IconNetwork },
      { label: "Field Data", to: "/field", icon: IconAntenna },
      { label: "Email security", to: "/email", icon: IconMail },
    ],
  },
  {
    label: "Operations",
    items: [
      { label: "Analytics and reports", to: "/analytics", icon: IconChartBar },
      { label: "AI security assistant", to: "/assistant", icon: IconMessageChatbot },
      { label: "Scheduled tasks", to: "/schedules", icon: IconCalendarTime },
    ],
  },
  {
    label: "Administration",
    items: [
      { label: "Integrations", to: "/integrations", icon: IconPlug },
      { label: "Settings and audit", to: "/settings", icon: IconSettings },
    ],
  },
];
