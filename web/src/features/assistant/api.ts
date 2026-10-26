import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type {
  AssistantReply,
  AssistantStatus,
  ConversationDetail,
  ConversationOut,
  CvssExplanation,
  FindingExplanation,
  ScanSummary,
} from "../../api/types";

export const assistantKeys = {
  status: ["assistant", "status"] as const,
  conversations: ["assistant", "conversations"] as const,
  conversation: (id: number) => ["assistant", "conversation", id] as const,
  explainFinding: (id: number) => ["assistant", "explain", "finding", id] as const,
  explainCvss: (vector: string) => ["assistant", "explain", "cvss", vector] as const,
};

export function useAssistantStatus() {
  return useQuery({
    queryKey: assistantKeys.status,
    queryFn: () => api.get<AssistantStatus>("/api/assistant/status"),
    staleTime: 30_000,
  });
}

export function useConversations() {
  return useQuery({
    queryKey: assistantKeys.conversations,
    queryFn: () => api.get<ConversationOut[]>("/api/assistant/conversations"),
  });
}

export function useConversation(id: number | null) {
  return useQuery({
    queryKey: assistantKeys.conversation(id ?? 0),
    queryFn: () => api.get<ConversationDetail>(`/api/assistant/conversations/${id}`),
    enabled: id !== null,
  });
}

export function useCreateConversation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (title?: string) => api.post<ConversationOut>("/api/assistant/conversations", { title: title ?? null }),
    onSuccess: () => qc.invalidateQueries({ queryKey: assistantKeys.conversations }),
  });
}

export function useDeleteConversation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.del(`/api/assistant/conversations/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: assistantKeys.conversations }),
  });
}

export function useSendMessage(conversationId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (content: string) =>
      api.post<AssistantReply>(`/api/assistant/conversations/${conversationId}/messages`, { content }),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: assistantKeys.conversation(conversationId) });
      void qc.invalidateQueries({ queryKey: assistantKeys.conversations });
    },
  });
}

export function useSummarizeScan() {
  return useMutation({
    mutationFn: (scanId: number) => api.post<ScanSummary>(`/api/assistant/summarize-scan/${scanId}`),
  });
}

export function useExplainFinding(findingId: number | null) {
  return useQuery({
    queryKey: assistantKeys.explainFinding(findingId ?? 0),
    queryFn: () => api.get<FindingExplanation>(`/api/assistant/explain/finding/${findingId}`),
    enabled: findingId !== null,
    staleTime: 60_000,
  });
}

export function useExplainCvss(vector: string | null) {
  return useQuery({
    queryKey: assistantKeys.explainCvss(vector ?? ""),
    queryFn: () => api.get<CvssExplanation>("/api/assistant/explain/cvss", { vector }),
    enabled: !!vector,
    retry: false,
    staleTime: Infinity,
  });
}
