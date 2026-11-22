import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError, apiStream } from "../../api/client";
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

/** What the assistant is doing right now, shown while an answer is still arriving. */
export interface StreamProgress {
  /** The answer so far. Empty while the model is still reading data. */
  text: string;
  /** Read-only tools the model has run for this answer, in order. */
  tools: string[];
}

export const EMPTY_PROGRESS: StreamProgress = { text: "", tools: [] };

/** Fold one server event into the progress shown on screen. Exported so the rules can be tested alone. */
export function applyStreamEvent(progress: StreamProgress, event: unknown): StreamProgress {
  if (typeof event !== "object" || event === null) return progress;
  const e = event as { type?: unknown; text?: unknown; name?: unknown };
  if (e.type === "delta" && typeof e.text === "string") return { ...progress, text: progress.text + e.text };
  if (e.type === "reset") return { ...progress, text: "" }; // the model was thinking aloud before using a tool
  if (e.type === "tool" && typeof e.name === "string") return { ...progress, tools: [...progress.tools, e.name] };
  return progress;
}

export function useSendMessage(conversationId: number) {
  const qc = useQueryClient();
  const [progress, setProgress] = useState<StreamProgress>(EMPTY_PROGRESS);
  const mutation = useMutation({
    mutationFn: async (content: string) => {
      setProgress(EMPTY_PROGRESS);
      let reply: AssistantReply | null = null;
      let failure: string | null = null;
      await apiStream(`/api/assistant/conversations/${conversationId}/messages/stream`, { content }, (event) => {
        const e = event as { type?: unknown; reply?: unknown; detail?: unknown };
        if (e.type === "done") reply = e.reply as AssistantReply;
        else if (e.type === "error") failure = typeof e.detail === "string" ? e.detail : "The assistant failed.";
        else setProgress((p) => applyStreamEvent(p, event));
      });
      if (failure !== null) throw new ApiError(503, failure);
      if (reply === null) throw new ApiError(0, "The answer stopped before it was complete. Ask again.");
      return reply as AssistantReply;
    },
    onSettled: () => {
      setProgress(EMPTY_PROGRESS);
      void qc.invalidateQueries({ queryKey: assistantKeys.conversation(conversationId) });
      void qc.invalidateQueries({ queryKey: assistantKeys.conversations });
    },
  });
  return { ...mutation, progress };
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
