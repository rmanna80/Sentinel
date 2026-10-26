import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ScanOut, ScheduleCreate, ScheduleOut, ScheduleUpdate } from "../../api/types";

export const scheduleKeys = { all: ["schedules"] as const, list: (d: number | null) => ["schedules", d] as const };

export function useSchedules(deviceId: number | null) {
  return useQuery({
    queryKey: scheduleKeys.list(deviceId),
    queryFn: () => api.get<ScheduleOut[]>("/api/schedules", { device_id: deviceId }),
    refetchInterval: 60_000,
  });
}

function useInvalidate() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: scheduleKeys.all });
    void qc.invalidateQueries({ queryKey: ["overview"] });
  };
}

export function useCreateSchedule() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (body: ScheduleCreate) => api.post<ScheduleOut>("/api/schedules", body),
    onSuccess: invalidate,
  });
}

export function useUpdateSchedule() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: ScheduleUpdate }) => api.patch<ScheduleOut>(`/api/schedules/${id}`, body),
    onSuccess: invalidate,
  });
}

export function useDeleteSchedule() {
  const invalidate = useInvalidate();
  return useMutation({ mutationFn: (id: number) => api.del(`/api/schedules/${id}`), onSuccess: invalidate });
}

export function useRunScheduleNow() {
  const qc = useQueryClient();
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (id: number) => api.post<ScanOut>(`/api/schedules/${id}/run-now`),
    onSuccess: () => {
      invalidate();
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}
