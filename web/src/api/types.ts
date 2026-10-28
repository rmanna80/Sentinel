// Friendly names for the generated OpenAPI types. Regenerate with `npm run gen:api`.
import type { components, paths } from "./schema";

type S = components["schemas"];

export type AuthState = S["AuthState"];
export type SetupRequest = S["SetupRequest"];
export type LoginRequest = S["LoginRequest"];
export type ChangePasswordRequest = S["ChangePasswordRequest"];

export type DeviceSummary = S["DeviceSummary"];
export type DeviceUpdate = S["DeviceUpdate"];
export type EnrollmentCode = S["EnrollmentCodeOut"];
export type MetricSeries = S["MetricSeries"];
export type MetricPoint = S["MetricPoint"];

export type ScanOut = S["ScanOut"];
export type ScanDetail = S["ScanDetail"];
export type ScanCreate = S["ScanCreate"];
export type ScanDiff = S["ScanDiff"];
export type CheckRunOut = S["CheckRunOut"];
export type CheckCatalogEntry = S["CheckCatalogEntry"];
export type ScanPage = S["Page_ScanOut_"];

export type FindingOut = S["FindingOut"];
export type FindingDetail = S["FindingDetail"];
export type FindingUpdate = S["FindingUpdate"];
export type FindingEvent = S["FindingEventOut"];
export type Observation = S["sentinel_server__schemas__ObservationOut"];
export type Evidence = S["EvidenceOut"];
export type Task = S["TaskOut"];
export type TaskCreate = S["TaskCreate"];
export type TaskUpdate = S["TaskUpdate"];
export type FindingPage = S["Page_FindingOut_"];

export type Overview = S["Overview"];
export type ScorePoint = S["ScorePoint"];
export type RecentEvent = S["RecentEvent"];

export type AuditEntry = S["AuditOut"];
export type AuditPage = S["Page_AuditOut_"];
export type AuditVerify = S["AuditVerify"];
export type SecretStatus = S["SecretStatus"];
export type OutboundEntry = S["OutboundOut"];
export type OutboundPage = S["Page_OutboundOut_"];

export type NotificationOut = S["NotificationOut"];
export type UnreadCount = S["UnreadCount"];
export type ReadAllResult = S["ReadAllResult"];
export type TestEmailResult = S["TestEmailResult"];

// Threat detection
export type AlertOut = S["AlertOut"];
export type AlertDetail = S["AlertDetail"];
export type AlertPage = S["AlertPage"];
export type AlertUpdate = S["AlertUpdate"];
export type IncidentOut = S["IncidentOut"];
export type IncidentDetail = S["IncidentDetail"];
export type IncidentPage = S["IncidentPage"];
export type IncidentUpdate = S["IncidentUpdate"];
export type RuleOut = S["RuleOut"];
export type IocIn = S["IocIn"];
export type IocList = S["IocList"];
export type IocImportResult = S["IocImportResult"];

// Logs
export type LogEventOut = S["LogEventOut"];
export type LogEventDetail = S["LogEventDetail"];
export type LogPage = S["LogPage"];
export type LogStats = S["LogStats"];

// Schedules
export type ScheduleOut = S["ScheduleOut"];
export type ScheduleCreate = S["ScheduleCreate"];
export type ScheduleUpdate = S["ScheduleUpdate"];

// Vulnerability intelligence and inventory
export type SoftwareOut = S["SoftwareOut"];
export type SoftwarePage = S["Page_SoftwareOut_"];
export type VulnSummary = S["VulnSummary"];
export type VulnDetail = S["VulnDetail"];
export type IntelStatus = S["IntelStatus"];
export type IntelSourceStatus = S["IntelSourceStatus"];
export type SyncRequest = S["SyncRequest"];
export type SyncAccepted = S["SyncAccepted"];

// Email security
export type EmailStatus = S["EmailStatus"];
export type IdentityOut = S["IdentityOut"];
export type IdentityCreate = S["IdentityCreate"];
export type EmailCheckOut = S["EmailCheckOut"];
export type EmailCheckResult = S["EmailCheckResult"];
export type DomainCheckOut = S["DomainCheckOut"];
export type DomainCheckResult = S["DomainCheckResult"];
export type PwnedRange = S["PwnedRange"];

// Network
export type ScopeOut = S["ScopeOut"];
export type ScopeCreate = S["ScopeCreate"];
export type ScopeUpdate = S["ScopeUpdate"];
export type NetworkScanRequest = S["NetworkScanRequest"];
export type NetworkScanCreate = S["NetworkScanCreate"];
export type NetworkPreview = S["NetworkPreview"];
export type NetworkSummary = S["NetworkSummary"];
export type NetworkFact = S["NetworkFact"];

// Assistant
export type AssistantStatus = S["AssistantStatus"];
export type ConversationOut = S["ConversationOut"];
export type ConversationDetail = S["ConversationDetail"];
export type MessageOut = S["MessageOut"];
export type AssistantReply = S["AssistantReply"];
export type ScanSummary = S["ScanSummary"];
export type FindingExplanation = S["FindingExplanation"];
export type CvssExplanation = S["CvssExplanation"];

// Analytics and reports
export type Analytics = S["Analytics"];
export type ReportOut = S["ReportOut"];
export type ReportCreate = S["ReportCreate"];

// Advisories (threat-intelligence feed)
export type AdvisoryOut = S["AdvisoryOut"];
export type AdvisoryPage = S["AdvisoryPage"];
export type AdvisoryUpdate = S["AdvisoryUpdate"];
export type FeedStatus = S["FeedStatus"];

// Behaviour (Sentinel X behavioural detections)
export type DetectionOut = S["DetectionOut"];
export type DetectionDetail = S["DetectionDetail"];
export type DetectionPage = S["DetectionPage"];
export type DetectionStatusUpdate = S["StatusUpdate"];
export type BehaviorSummary = S["BehaviorSummary"];
export type RuleCount = S["RuleCount"];

// Field data (passive Wi-Fi/RF/host surveys)
export type CaptureOut = S["CaptureOut"];
export type CaptureDetail = S["CaptureDetail"];
export type CaptureIn = S["CaptureIn"];
export type CapturePage = S["CapturePage"];
export type FieldSummary = S["FieldSummary"];
export type KnownNetworks = S["KnownNetworks"];
export type FieldObservation = S["sentinel_server__phases__field_data__ObservationOut"];
export type ObservationIn = S["ObservationIn"];

type QueryOf<P extends keyof paths> = paths[P] extends { get: { parameters: { query?: infer Q } } }
  ? NonNullable<Q>
  : never;

export type FindingsQuery = QueryOf<"/api/findings">;
export type ScansQuery = QueryOf<"/api/scans">;
export type AuditQuery = QueryOf<"/api/audit">;
export type OutboundQuery = QueryOf<"/api/outbound">;
export type OverviewQuery = QueryOf<"/api/dashboard/overview">;
export type AlertsQuery = QueryOf<"/api/alerts">;
export type IncidentsQuery = QueryOf<"/api/incidents">;
export type LogsQuery = QueryOf<"/api/logs">;
export type SoftwareQuery = QueryOf<"/api/software">;
export type AnalyticsQuery = QueryOf<"/api/analytics">;
export type ExportFindingsQuery = QueryOf<"/api/export/findings">;
export type AdvisoriesQuery = QueryOf<"/api/advisories">;
export type CapturesQuery = QueryOf<"/api/field/captures">;
export type DetectionsQuery = QueryOf<"/api/behavior/detections">;
