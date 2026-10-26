import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type {
  DomainCheckOut,
  DomainCheckResult,
  EmailCheckOut,
  EmailCheckResult,
  EmailStatus,
  IdentityCreate,
  IdentityOut,
  PwnedRange,
} from "../../api/types";

export const emailKeys = {
  all: ["email"] as const,
  status: ["email", "status"] as const,
  identities: ["email", "identities"] as const,
  history: (id: number) => ["email", "history", id] as const,
  domains: ["email", "domains"] as const,
};

export function useEmailStatus() {
  return useQuery({ queryKey: emailKeys.status, queryFn: () => api.get<EmailStatus>("/api/email/status") });
}

export function useIdentities() {
  return useQuery({ queryKey: emailKeys.identities, queryFn: () => api.get<IdentityOut[]>("/api/email/identities") });
}

export function useAddIdentity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: IdentityCreate) => api.post<IdentityOut>("/api/email/identities", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: emailKeys.identities }),
  });
}

export function useDeleteIdentity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.del(`/api/email/identities/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: emailKeys.identities }),
  });
}

export function useCheckIdentity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.post<EmailCheckResult>(`/api/email/identities/${id}/check`),
    onSuccess: (_d, id) => {
      void qc.invalidateQueries({ queryKey: emailKeys.identities });
      void qc.invalidateQueries({ queryKey: emailKeys.history(id) });
    },
  });
}

export function useIdentityHistory(id: number | null) {
  return useQuery({
    queryKey: emailKeys.history(id ?? 0),
    queryFn: () => api.get<EmailCheckOut[]>(`/api/email/identities/${id}/history`),
    enabled: id !== null,
  });
}

export function useDomainChecks() {
  return useQuery({ queryKey: emailKeys.domains, queryFn: () => api.get<DomainCheckOut[]>("/api/email/domains", { limit: 50 }) });
}

export function useCheckDomain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (domain: string) => api.post<DomainCheckResult>(`/api/email/domains/${encodeURIComponent(domain)}/check`),
    onSuccess: () => qc.invalidateQueries({ queryKey: emailKeys.domains }),
  });
}

/** Only ever called with the 5-character hash prefix. */
export function fetchPwnedRange(prefix: string): Promise<PwnedRange> {
  if (!/^[0-9A-F]{5}$/.test(prefix)) return Promise.reject(new Error("Only a 5-character hash prefix may be sent."));
  return api.get<PwnedRange>(`/api/email/pwned-range/${prefix}`);
}
