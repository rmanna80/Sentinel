import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type {
  BehaviorSummary,
  DetectionDetail,
  DetectionPage,
  DetectionStatusUpdate,
  DetectionsQuery,
} from "../../api/types";

export const behaviorKeys = {
  all: ["behavior"] as const,
  summary: ["behavior", "summary"] as const,
  list: (q: DetectionsQuery) => ["behavior", "list", q] as const,
  detail: (id: number) => ["behavior", "detail", id] as const,
};

/** The status select maps to the server's filter semantics: the default view omits the param (which hides
 * dismissed), so only an explicit status or "all" is sent. */
export interface DetectionFilters {
  status: string;
  severity?: string;
  host?: string;
  q?: string;
  limit: number;
  offset: number;
}

export function buildDetectionsQuery(f: DetectionFilters): DetectionsQuery {
  return {
    // "open" is the server default (new + acknowledged, dismissed hidden), sent as no status param.
    status: f.status === "open" ? undefined : f.status,
    severity: f.severity || undefined,
    host: f.host || undefined,
    q: f.q?.trim() || undefined,
    limit: f.limit,
    offset: f.offset,
  };
}

export function useBehaviorSummary() {
  return useQuery({
    queryKey: behaviorKeys.summary,
    queryFn: () => api.get<BehaviorSummary>("/api/behavior/summary"),
  });
}

export function useDetections(q: DetectionsQuery) {
  return useQuery({
    queryKey: behaviorKeys.list(q),
    queryFn: () => api.get<DetectionPage>("/api/behavior/detections", q),
    placeholderData: (prev) => prev,
  });
}

export function useDetection(id: number | null) {
  return useQuery({
    queryKey: behaviorKeys.detail(id ?? 0),
    queryFn: () => api.get<DetectionDetail>(`/api/behavior/detections/${id}`),
    enabled: id !== null,
  });
}

export function useUpdateDetection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: DetectionStatusUpdate }) =>
      api.patch<DetectionDetail>(`/api/behavior/detections/${id}`, body),
    onSuccess: (data) => {
      qc.setQueryData(behaviorKeys.detail(data.id), data);
      void qc.invalidateQueries({ queryKey: ["behavior", "list"] });
      void qc.invalidateQueries({ queryKey: behaviorKeys.summary });
    },
  });
}
