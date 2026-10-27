import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type {
  CaptureDetail,
  CaptureIn,
  CapturePage,
  CapturesQuery,
  FieldSummary,
  KnownNetworks,
} from "../../api/types";

export const fieldKeys = {
  all: ["field"] as const,
  summary: ["field", "summary"] as const,
  captures: (q: CapturesQuery) => ["field", "captures", q] as const,
  capture: (id: number) => ["field", "capture", id] as const,
  known: ["field", "known-networks"] as const,
};

export function useFieldSummary() {
  return useQuery({
    queryKey: fieldKeys.summary,
    queryFn: () => api.get<FieldSummary>("/api/field/summary"),
  });
}

export function useCaptures(q: CapturesQuery) {
  return useQuery({
    queryKey: fieldKeys.captures(q),
    queryFn: () => api.get<CapturePage>("/api/field/captures", q),
    placeholderData: (prev) => prev,
  });
}

export function useCapture(id: number | null) {
  return useQuery({
    queryKey: fieldKeys.capture(id ?? 0),
    queryFn: () => api.get<CaptureDetail>(`/api/field/captures/${id}`),
    enabled: id !== null,
  });
}

export function useCreateCapture() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CaptureIn) => api.post<CaptureDetail>("/api/field/captures", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: fieldKeys.summary });
      void qc.invalidateQueries({ queryKey: ["field", "captures"] });
    },
  });
}

export function useDeleteCapture() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.del(`/api/field/captures/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: fieldKeys.summary });
      void qc.invalidateQueries({ queryKey: ["field", "captures"] });
    },
  });
}

export function useKnownNetworks() {
  return useQuery({
    queryKey: fieldKeys.known,
    queryFn: () => api.get<KnownNetworks>("/api/field/known-networks"),
  });
}

export function useSaveKnownNetworks() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: KnownNetworks) => api.put<KnownNetworks>("/api/field/known-networks", body),
    onSuccess: (data) => {
      qc.setQueryData(fieldKeys.known, data);
      void qc.invalidateQueries({ queryKey: fieldKeys.summary });
    },
  });
}
