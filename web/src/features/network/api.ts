import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type {
  NetworkPreview,
  NetworkScanCreate,
  NetworkScanRequest,
  NetworkSummary,
  ScanOut,
  ScopeCreate,
  ScopeOut,
  ScopeUpdate,
} from "../../api/types";

export const networkKeys = {
  scope: ["network", "scope"] as const,
  summary: (id: number) => ["network", "summary", id] as const,
};

export function useScope() {
  return useQuery({ queryKey: networkKeys.scope, queryFn: () => api.get<ScopeOut[]>("/api/network/scope") });
}

export function useAddScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ScopeCreate) => api.post<ScopeOut>("/api/network/scope", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: networkKeys.scope }),
  });
}

export function useUpdateScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: ScopeUpdate }) => api.patch<ScopeOut>(`/api/network/scope/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: networkKeys.scope }),
  });
}

export function useDeleteScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.del(`/api/network/scope/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: networkKeys.scope }),
  });
}

export function usePreviewNetworkScan() {
  return useMutation({ mutationFn: (body: NetworkScanRequest) => api.post<NetworkPreview>("/api/network/preview", body) });
}

export function useStartNetworkScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: NetworkScanCreate) => api.post<ScanOut>("/api/network/scans", body),
    onSuccess: (_d, body) => {
      void qc.invalidateQueries({ queryKey: networkKeys.summary(body.device_id) });
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

export function useNetworkSummary(deviceId: number | null) {
  return useQuery({
    queryKey: networkKeys.summary(deviceId ?? 0),
    queryFn: () => api.get<NetworkSummary>("/api/network/summary", { device_id: deviceId }),
    enabled: deviceId !== null,
  });
}

/**
 * The API refuses a public target until the person types an exact authorization sentence, and states that
 * sentence in its error: ... To add it, type exactly: "I am authorized to test 203.0.113.5"
 */
export function requiredSentence(message: string): string | null {
  const m = /type exactly:\s*"([^"]+)"/i.exec(message);
  return m ? m[1] : null;
}
