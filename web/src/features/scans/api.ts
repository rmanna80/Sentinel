import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { CheckCatalogEntry, ScanCreate, ScanDetail, ScanDiff, ScanOut, ScanPage, ScansQuery } from "../../api/types";

export const scanKeys = {
  all: ["scans"] as const,
  list: (q: ScansQuery) => ["scans", "list", q] as const,
  detail: (id: number) => ["scans", "detail", id] as const,
  diff: (id: number, against: number) => ["scans", "diff", id, against] as const,
  checks: ["checks"] as const,
};

export const ACTIVE_SCAN = new Set(["queued", "running"]);

export function useScans(q: ScansQuery, opts: { poll?: boolean } = {}) {
  return useQuery({
    queryKey: scanKeys.list(q),
    queryFn: () => api.get<ScanPage>("/api/scans", q),
    placeholderData: (prev) => prev,
    refetchInterval: (query) =>
      opts.poll || query.state.data?.items.some((s) => ACTIVE_SCAN.has(s.status)) ? 5_000 : false,
  });
}

export function useScan(id: number) {
  return useQuery({
    queryKey: scanKeys.detail(id),
    queryFn: () => api.get<ScanDetail>(`/api/scans/${id}`),
    // Live progress: poll while the scan is queued or running.
    refetchInterval: (query) => (query.state.data && ACTIVE_SCAN.has(query.state.data.status) ? 2_000 : false),
  });
}

export function useScanDiff(id: number, against: number | null) {
  return useQuery({
    queryKey: scanKeys.diff(id, against ?? 0),
    queryFn: () => api.get<ScanDiff>(`/api/scans/${id}/diff`, { against }),
    enabled: against !== null,
  });
}

export function useCheckCatalog() {
  return useQuery({
    queryKey: scanKeys.checks,
    queryFn: () => api.get<CheckCatalogEntry[]>("/api/checks"),
    staleTime: 60_000,
  });
}

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ScanCreate) => api.post<ScanOut>("/api/scans", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: scanKeys.all });
      void qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}

export function useCancelScan(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<ScanOut>(`/api/scans/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: scanKeys.all }),
  });
}

/** The export is a JSON document; the server records an audit entry for each export. */
export function fetchScanExport(id: number): Promise<unknown> {
  return api.get<unknown>(`/api/scans/${id}/export`);
}
