import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { AuditPage, AuditQuery, AuditVerify, ChangePasswordRequest } from "../../api/types";

/*
 * GET /api/settings returns an untyped object in the OpenAPI schema. These interfaces mirror the server's
 * DEFAULTS in services/app_settings.py; values are narrowed at runtime before use.
 */
export interface NotificationSettings {
  min_severity: string;
  quiet_hours_enabled: boolean;
  quiet_start: string;
  quiet_end: string;
  timezone: string;
  email_enabled: boolean;
  email_to: string;
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_from: string;
  smtp_starttls: boolean;
}

export interface RetentionSettings {
  log_event_days: number;
  metric_days: number;
}

export interface IntegrationToggle {
  enabled: boolean;
  [extra: string]: unknown;
}

export type IntegrationSettings = Record<string, IntegrationToggle>;

export interface AppSettings {
  notifications?: Partial<NotificationSettings>;
  integrations?: IntegrationSettings;
  retention?: Partial<RetentionSettings>;
  [group: string]: unknown;
}

export const settingsKeys = {
  all: ["settings"] as const,
  audit: (q: AuditQuery) => ["audit", q] as const,
  verify: ["audit", "verify"] as const,
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function parseSettings(raw: unknown): AppSettings {
  if (!isRecord(raw)) return {};
  const out: AppSettings = { ...raw };
  if (isRecord(raw.integrations)) {
    const integrations: IntegrationSettings = {};
    for (const [name, value] of Object.entries(raw.integrations)) {
      if (isRecord(value)) integrations[name] = { ...value, enabled: value.enabled === true };
    }
    out.integrations = integrations;
  }
  return out;
}

export function useAppSettings() {
  return useQuery({
    queryKey: settingsKeys.all,
    queryFn: async () => parseSettings(await api.get<unknown>("/api/settings")),
  });
}

export function useSaveSetting(key: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.put<unknown>(`/api/settings/${key}`, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: settingsKeys.all });
      void qc.invalidateQueries({ queryKey: ["audit"] });
    },
  });
}

export function useAudit(q: AuditQuery) {
  return useQuery({
    queryKey: settingsKeys.audit(q),
    queryFn: () => api.get<AuditPage>("/api/audit", q),
    placeholderData: (prev) => prev,
  });
}

export function useVerifyAudit() {
  return useMutation({
    mutationFn: () => api.get<AuditVerify>("/api/audit/verify"),
  });
}

export function useChangePassword() {
  return useMutation({
    mutationFn: (body: ChangePasswordRequest) => api.post<void>("/api/auth/change-password", body),
  });
}
