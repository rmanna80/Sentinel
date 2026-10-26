import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type {
  FindingDetail,
  FindingPage,
  FindingsQuery,
  FindingUpdate,
  IntelStatus,
  ScanOut,
  SoftwarePage,
  SoftwareQuery,
  SyncAccepted,
  SyncRequest,
  Task,
  TaskCreate,
  TaskUpdate,
  VulnDetail,
  VulnSummary,
} from "../../api/types";

export const findingKeys = {
  all: ["findings"] as const,
  list: (q: FindingsQuery) => ["findings", "list", q] as const,
  detail: (id: number) => ["findings", "detail", id] as const,
};

export function useFindings(q: FindingsQuery) {
  return useQuery({
    queryKey: findingKeys.list(q),
    queryFn: () => api.get<FindingPage>("/api/findings", q),
    placeholderData: (prev) => prev,
  });
}

export function useFinding(id: number) {
  return useQuery({
    queryKey: findingKeys.detail(id),
    queryFn: () => api.get<FindingDetail>(`/api/findings/${id}`),
  });
}

function useInvalidateFinding(id: number) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: findingKeys.all });
    void qc.invalidateQueries({ queryKey: ["overview"] });
    void qc.invalidateQueries({ queryKey: findingKeys.detail(id) });
  };
}

export function useUpdateFinding(id: number) {
  const qc = useQueryClient();
  const invalidate = useInvalidateFinding(id);
  return useMutation({
    mutationFn: (body: FindingUpdate) => api.patch<FindingDetail>(`/api/findings/${id}`, body),
    onSuccess: (data) => {
      qc.setQueryData(findingKeys.detail(id), data);
      invalidate();
    },
  });
}

export function useVerifyFinding(id: number) {
  const qc = useQueryClient();
  const invalidate = useInvalidateFinding(id);
  return useMutation({
    mutationFn: () => api.post<ScanOut>(`/api/findings/${id}/verify`),
    onSuccess: () => {
      invalidate();
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

export function useCreateTask(findingId: number) {
  const invalidate = useInvalidateFinding(findingId);
  return useMutation({
    mutationFn: (body: TaskCreate) => api.post<Task>(`/api/findings/${findingId}/tasks`, body),
    onSuccess: invalidate,
  });
}

export function useUpdateTask(findingId: number) {
  const invalidate = useInvalidateFinding(findingId);
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: TaskUpdate }) => api.patch<Task>(`/api/tasks/${id}`, body),
    onSuccess: invalidate,
  });
}

// ---------------------------------------------------------------- inventory and vulnerability intelligence

export const vulnKeys = {
  summary: (deviceId: number | null) => ["vulns", "summary", deviceId] as const,
  software: (q: SoftwareQuery) => ["vulns", "software", q] as const,
  detail: (id: string) => ["vulns", "detail", id] as const,
  intel: ["vulns", "intel"] as const,
};

export function useVulnSummary(deviceId: number | null) {
  return useQuery({
    queryKey: vulnKeys.summary(deviceId),
    queryFn: () => api.get<VulnSummary>("/api/vulnerabilities/summary", { device_id: deviceId }),
  });
}

export function useSoftware(q: SoftwareQuery) {
  return useQuery({
    queryKey: vulnKeys.software(q),
    queryFn: () => api.get<SoftwarePage>("/api/software", q),
    placeholderData: (prev) => prev,
  });
}

export function useVulnDetail(vulnId: string | null | undefined) {
  return useQuery({
    queryKey: vulnKeys.detail(vulnId ?? ""),
    queryFn: () => api.get<VulnDetail>(`/api/vulns/${encodeURIComponent(vulnId ?? "")}`),
    enabled: !!vulnId,
    retry: false,
  });
}

export function useIntelStatus() {
  return useQuery({
    queryKey: vulnKeys.intel,
    queryFn: () => api.get<IntelStatus>("/api/intel/status"),
    refetchInterval: (q) => (q.state.data?.sources.some((s) => s.sync_requested) ? 5_000 : 60_000),
  });
}

export function useIntelSync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SyncRequest) => api.post<SyncAccepted>("/api/intel/sync", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vulns"] }),
  });
}
