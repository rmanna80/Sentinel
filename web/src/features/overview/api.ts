import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { Overview } from "../../api/types";

export const overviewKeys = {
  all: ["overview"] as const,
  detail: (deviceId: number | null, days: number) => ["overview", deviceId, days] as const,
};

export function useOverview(deviceId: number | null, days: number) {
  return useQuery({
    queryKey: overviewKeys.detail(deviceId, days),
    queryFn: () => api.get<Overview>("/api/dashboard/overview", { device_id: deviceId, days }),
    placeholderData: (prev) => prev,
    refetchInterval: 30_000,
  });
}
