import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, isApiError } from "../../api/client";
import type { NotificationOut, TestEmailResult, UnreadCount } from "../../api/types";

export const notificationKeys = {
  all: ["notifications"] as const,
  unread: ["notifications", "unread"] as const,
  list: (limit: number) => ["notifications", "list", limit] as const,
};

/**
 * Unread count, or null when the server has no notifications module (404): the bell is then hidden.
 */
export function useUnreadCount() {
  return useQuery({
    queryKey: notificationKeys.unread,
    queryFn: async (): Promise<UnreadCount | null> => {
      try {
        return await api.get<UnreadCount>("/api/notifications/unread-count");
      } catch (err) {
        if (isApiError(err, 404)) return null;
        throw err;
      }
    },
    refetchInterval: 60_000,
    retry: false,
  });
}

export function useNotificationList(enabled: boolean, limit = 30) {
  return useQuery({
    queryKey: notificationKeys.list(limit),
    queryFn: () => api.get<NotificationOut[]>("/api/notifications", { limit }),
    enabled,
  });
}

export function useMarkRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.post<NotificationOut>(`/api/notifications/${id}/read`),
    onSuccess: () => qc.invalidateQueries({ queryKey: notificationKeys.all }),
  });
}

export function useMarkAllRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<{ marked: number }>("/api/notifications/read-all"),
    onSuccess: () => qc.invalidateQueries({ queryKey: notificationKeys.all }),
  });
}

export function useTestEmail() {
  return useMutation({
    mutationFn: () => api.post<TestEmailResult>("/api/notifications/test-email"),
  });
}
