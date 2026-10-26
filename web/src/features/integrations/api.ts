import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { OutboundPage, OutboundQuery, SecretStatus } from "../../api/types";

export { useAppSettings, useSaveSetting } from "../settings/api";

export const integrationKeys = {
  secrets: ["secrets"] as const,
  outbound: (q: OutboundQuery) => ["outbound", q] as const,
};

export function useSecrets() {
  return useQuery({ queryKey: integrationKeys.secrets, queryFn: () => api.get<SecretStatus[]>("/api/secrets") });
}

export function useSetSecret() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, value }: { name: string; value: string }) =>
      api.put<SecretStatus>(`/api/secrets/${name}`, { value }),
    onSuccess: () => qc.invalidateQueries({ queryKey: integrationKeys.secrets }),
  });
}

export function useDeleteSecret() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.del(`/api/secrets/${name}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: integrationKeys.secrets }),
  });
}

export function useOutbound(q: OutboundQuery) {
  return useQuery({
    queryKey: integrationKeys.outbound(q),
    queryFn: () => api.get<OutboundPage>("/api/outbound", q),
    placeholderData: (prev) => prev,
  });
}
