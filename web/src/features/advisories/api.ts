import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { AdvisoriesQuery, AdvisoryOut, AdvisoryPage, AdvisoryUpdate, FeedStatus } from "../../api/types";

export const advisoryKeys = {
  all: ["advisories"] as const,
  list: (q: AdvisoriesQuery) => ["advisories", "list", q] as const,
  detail: (id: number) => ["advisories", "detail", id] as const,
  summary: ["advisories", "summary"] as const,
};

export function useAdvisories(q: AdvisoriesQuery) {
  return useQuery({
    queryKey: advisoryKeys.list(q),
    queryFn: () => api.get<AdvisoryPage>("/api/advisories", q),
    placeholderData: (prev) => prev,
  });
}

export function useAdvisorySummary() {
  return useQuery({
    queryKey: advisoryKeys.summary,
    queryFn: () => api.get<FeedStatus>("/api/advisories/summary"),
  });
}

/** Opening an advisory marks it read on the server, so loading the detail also refreshes the counts. */
export function useAdvisory(id: number | null) {
  const qc = useQueryClient();
  return useQuery({
    queryKey: advisoryKeys.detail(id ?? 0),
    queryFn: async () => {
      const data = await api.get<AdvisoryOut>(`/api/advisories/${id}`);
      // The GET marked it read; refresh the list and the counts without re-reading this detail.
      void qc.invalidateQueries({ queryKey: ["advisories", "list"] });
      void qc.invalidateQueries({ queryKey: advisoryKeys.summary });
      return data;
    },
    enabled: id !== null,
  });
}

export function useUpdateAdvisory() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: AdvisoryUpdate }) =>
      api.patch<AdvisoryOut>(`/api/advisories/${id}`, body),
    onSuccess: (data) => {
      qc.setQueryData(advisoryKeys.detail(data.id), data);
      void qc.invalidateQueries({ queryKey: advisoryKeys.all });
    },
  });
}

export function useRefreshFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<FeedStatus>("/api/intel/feed/refresh"),
    onSuccess: (data) => {
      qc.setQueryData(advisoryKeys.summary, data);
      void qc.invalidateQueries({ queryKey: advisoryKeys.all });
    },
  });
}
