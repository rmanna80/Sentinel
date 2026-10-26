import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { Analytics, AnalyticsQuery, ReportCreate, ReportOut } from "../../api/types";

export const analyticsKeys = {
  analytics: (q: AnalyticsQuery) => ["analytics", q] as const,
  reports: ["reports"] as const,
};

export function useAnalytics(q: AnalyticsQuery) {
  return useQuery({
    queryKey: analyticsKeys.analytics(q),
    queryFn: () => api.get<Analytics>("/api/analytics", q),
    placeholderData: (prev) => prev,
  });
}

export function useReports() {
  return useQuery({ queryKey: analyticsKeys.reports, queryFn: () => api.get<ReportOut[]>("/api/reports") });
}

export function useCreateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ReportCreate) => api.post<ReportOut>("/api/reports", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: analyticsKeys.reports }),
  });
}

export function useDeleteReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.del(`/api/reports/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: analyticsKeys.reports }),
  });
}
