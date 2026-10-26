import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { DeviceSummary, DeviceUpdate, EnrollmentCode, MetricSeries } from "../../api/types";

export const deviceKeys = {
  all: ["devices"] as const,
  list: (includeRevoked: boolean) => ["devices", "list", includeRevoked] as const,
  detail: (id: number) => ["devices", "detail", id] as const,
  metrics: (id: number, hours: number) => ["devices", "metrics", id, hours] as const,
};

export function useDevices(includeRevoked = false) {
  return useQuery({
    queryKey: deviceKeys.list(includeRevoked),
    queryFn: () => api.get<DeviceSummary[]>("/api/devices", { include_revoked: includeRevoked || undefined }),
    refetchInterval: 30_000,
  });
}

export function useDevice(id: number) {
  return useQuery({
    queryKey: deviceKeys.detail(id),
    queryFn: () => api.get<DeviceSummary>(`/api/devices/${id}`),
    refetchInterval: 30_000,
  });
}

export function useDeviceMetrics(id: number | null, hours: number) {
  return useQuery({
    queryKey: deviceKeys.metrics(id ?? 0, hours),
    queryFn: () => api.get<MetricSeries[]>(`/api/devices/${id}/metrics`, { hours }),
    enabled: id !== null,
    refetchInterval: 60_000,
  });
}

export function useRenameDevice(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DeviceUpdate) => api.patch<DeviceSummary>(`/api/devices/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: deviceKeys.all }),
  });
}

export function useRevokeDevice(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.del(`/api/devices/${id}`),
    onSuccess: () => qc.invalidateQueries(),
  });
}

export function useCreateEnrollmentCode() {
  return useMutation({
    mutationFn: () => api.post<EnrollmentCode>("/api/devices/enrollment-codes"),
  });
}
