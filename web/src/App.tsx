import { lazy, type ComponentType } from "react";
import { createBrowserRouter, Link, RouterProvider } from "react-router";
import { AuthProvider } from "./auth/AuthContext";
import { AuthError, AuthLoading, SignedOut } from "./auth/AuthScreens";
import { Empty, PageHeader, Panel } from "./components/Page";
import { AppLayout } from "./layout/AppLayout";
import { DeviceScopeProvider } from "./layout/DeviceScope";
import { OverviewPage } from "./features/overview/OverviewPage";

// Each section loads on first visit, so the overview opens without pulling in every page.
function page<K extends string>(loader: () => Promise<Record<K, ComponentType>>, name: K) {
  return lazy(async () => ({ default: (await loader())[name] }));
}

const ScansPage = page(() => import("./features/scans/ScansPage"), "ScansPage");
const ScanDetailPage = page(() => import("./features/scans/ScanDetailPage"), "ScanDetailPage");
const VulnerabilitiesPage = page(() => import("./features/vulnerabilities/VulnerabilitiesPage"), "VulnerabilitiesPage");
const FindingDetailPage = page(() => import("./features/vulnerabilities/FindingDetailPage"), "FindingDetailPage");
const DevicesPage = page(() => import("./features/devices/DevicesPage"), "DevicesPage");
const DeviceDetailPage = page(() => import("./features/devices/DeviceDetailPage"), "DeviceDetailPage");
const DiagnosticsPage = page(() => import("./features/diagnostics/DiagnosticsPage"), "DiagnosticsPage");
const ThreatsPage = page(() => import("./features/threats/ThreatsPage"), "ThreatsPage");
const AlertDetailPage = page(() => import("./features/threats/AlertDetailPage"), "AlertDetailPage");
const IncidentDetailPage = page(() => import("./features/threats/IncidentDetailPage"), "IncidentDetailPage");
const LogsPage = page(() => import("./features/logs/LogsPage"), "LogsPage");
const NetworkPage = page(() => import("./features/network/NetworkPage"), "NetworkPage");
const EmailPage = page(() => import("./features/email/EmailPage"), "EmailPage");
const AnalyticsPage = page(() => import("./features/analytics/AnalyticsPage"), "AnalyticsPage");
const AssistantPage = page(() => import("./features/assistant/AssistantPage"), "AssistantPage");
const SchedulesPage = page(() => import("./features/schedules/SchedulesPage"), "SchedulesPage");
const IntegrationsPage = page(() => import("./features/integrations/IntegrationsPage"), "IntegrationsPage");
const SettingsPage = page(() => import("./features/settings/SettingsPage"), "SettingsPage");

function NotFound() {
  return (
    <>
      <PageHeader title="Page not found" />
      <Panel>
        <Empty
          title="There's nothing at this address"
          action={
            <Link to="/" className="sn-link">
              Go to the overview
            </Link>
          }
        />
      </Panel>
    </>
  );
}

const router = createBrowserRouter([
  {
    path: "/",
    element: <AppLayout />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: "scans", element: <ScansPage /> },
      { path: "scans/:scanId", element: <ScanDetailPage /> },
      { path: "vulnerabilities", element: <VulnerabilitiesPage /> },
      { path: "vulnerabilities/:findingId", element: <FindingDetailPage /> },
      { path: "devices", element: <DevicesPage /> },
      { path: "devices/:deviceId", element: <DeviceDetailPage /> },
      { path: "diagnostics", element: <DiagnosticsPage /> },
      { path: "threats", element: <ThreatsPage /> },
      { path: "threats/alerts/:alertId", element: <AlertDetailPage /> },
      { path: "threats/incidents/:incidentId", element: <IncidentDetailPage /> },
      { path: "logs", element: <LogsPage /> },
      { path: "network", element: <NetworkPage /> },
      { path: "email", element: <EmailPage /> },
      { path: "analytics", element: <AnalyticsPage /> },
      { path: "assistant", element: <AssistantPage /> },
      { path: "schedules", element: <SchedulesPage /> },
      { path: "integrations", element: <IntegrationsPage /> },
      { path: "settings", element: <SettingsPage /> },
      { path: "*", element: <NotFound /> },
    ],
  },
]);

export function App() {
  return (
    <AuthProvider
      renderLoading={() => <AuthLoading />}
      renderError={(error, retry) => <AuthError error={error} retry={retry} />}
      renderSignedOut={(state) => <SignedOut state={state} />}
    >
      <DeviceScopeProvider>
        <RouterProvider router={router} />
      </DeviceScopeProvider>
    </AuthProvider>
  );
}
