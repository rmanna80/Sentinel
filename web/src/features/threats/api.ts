import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type {
  AlertDetail,
  AlertPage,
  AlertsQuery,
  AlertUpdate,
  IncidentDetail,
  IncidentPage,
  IncidentsQuery,
  IncidentUpdate,
  IocImportResult,
  IocIn,
  IocList,
  RuleOut,
} from "../../api/types";

export const threatKeys = {
  all: ["threats"] as const,
  alerts: (q: AlertsQuery) => ["threats", "alerts", q] as const,
  alert: (id: number) => ["threats", "alert", id] as const,
  incidents: (q: IncidentsQuery) => ["threats", "incidents", q] as const,
  incident: (id: number) => ["threats", "incident", id] as const,
  rules: ["threats", "rules"] as const,
  iocs: ["threats", "iocs"] as const,
};

export const ALERT_STATUSES = ["new", "acknowledged", "investigating", "resolved", "false_positive"] as const;
export const INCIDENT_STATUSES = ["open", "investigating", "closed"] as const;

export function useAlerts(q: AlertsQuery) {
  return useQuery({
    queryKey: threatKeys.alerts(q),
    queryFn: () => api.get<AlertPage>("/api/alerts", q),
    placeholderData: (prev) => prev,
    refetchInterval: 30_000,
  });
}

export function useAlert(id: number) {
  return useQuery({ queryKey: threatKeys.alert(id), queryFn: () => api.get<AlertDetail>(`/api/alerts/${id}`) });
}

export function useUpdateAlert(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AlertUpdate) => api.patch<AlertDetail>(`/api/alerts/${id}`, body),
    onSuccess: (data) => {
      qc.setQueryData(threatKeys.alert(id), data);
      void qc.invalidateQueries({ queryKey: threatKeys.all });
      void qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}

export function useIncidents(q: IncidentsQuery) {
  return useQuery({
    queryKey: threatKeys.incidents(q),
    queryFn: () => api.get<IncidentPage>("/api/incidents", q),
    placeholderData: (prev) => prev,
  });
}

export function useIncident(id: number) {
  return useQuery({ queryKey: threatKeys.incident(id), queryFn: () => api.get<IncidentDetail>(`/api/incidents/${id}`) });
}

export function useUpdateIncident(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: IncidentUpdate) => api.patch<IncidentDetail>(`/api/incidents/${id}`, body),
    onSuccess: (data) => {
      qc.setQueryData(threatKeys.incident(id), data);
      void qc.invalidateQueries({ queryKey: threatKeys.all });
    },
  });
}

export function useRules() {
  return useQuery({ queryKey: threatKeys.rules, queryFn: () => api.get<RuleOut[]>("/api/rules") });
}

export function useToggleRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch<RuleOut>(`/api/rules/${encodeURIComponent(id)}`, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: threatKeys.rules }),
  });
}

export function useIocs() {
  return useQuery({ queryKey: threatKeys.iocs, queryFn: () => api.get<IocList>("/api/iocs") });
}

export function useImportIocs() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (items: IocIn[]) => api.post<IocImportResult>("/api/iocs", items),
    onSuccess: () => qc.invalidateQueries({ queryKey: threatKeys.iocs }),
  });
}

export function useDeleteIoc() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (sha256: string) => api.del(`/api/iocs/${sha256}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: threatKeys.iocs }),
  });
}

/** Parse pasted text: one SHA-256 per line, optionally followed by a label (comma, tab or spaces). */
export function parseIocText(text: string): { items: IocIn[]; invalid: string[] } {
  const items: IocIn[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([0-9A-Fa-f]{64})(?:[\s,;]+(.*))?$/.exec(line);
    if (!m) {
      invalid.push(line.length > 80 ? `${line.slice(0, 80)}…` : line);
      continue;
    }
    const sha = m[1].toLowerCase();
    if (seen.has(sha)) continue;
    seen.add(sha);
    const label = m[2]?.trim().slice(0, 255);
    items.push({ sha256: sha, label: label || null });
  }
  return { items, invalid };
}
