import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { LogEventDetail, LogPage, LogsQuery, LogStats } from "../../api/types";

export const logKeys = {
  search: (q: LogsQuery) => ["logs", "search", q] as const,
  event: (id: number) => ["logs", "event", id] as const,
  stats: (days: number, deviceId: number | null) => ["logs", "stats", days, deviceId] as const,
};

export function useLogSearch(q: LogsQuery) {
  return useQuery({
    queryKey: logKeys.search(q),
    queryFn: () => api.get<LogPage>("/api/logs", q),
    placeholderData: (prev) => prev,
  });
}

export function useLogEvent(id: number | null) {
  return useQuery({
    queryKey: logKeys.event(id ?? 0),
    queryFn: () => api.get<LogEventDetail>(`/api/logs/${id}`),
    enabled: id !== null,
  });
}

export function useLogStats(days: number, deviceId: number | null) {
  return useQuery({
    queryKey: logKeys.stats(days, deviceId),
    queryFn: () => api.get<LogStats>("/api/logs/stats", { days, device_id: deviceId }),
  });
}
