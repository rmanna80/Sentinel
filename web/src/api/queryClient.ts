import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./client";

const NO_RETRY = new Set([400, 401, 403, 404, 409, 421, 422, 429]);

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: true,
        retry: (count, err) => !(err instanceof ApiError && NO_RETRY.has(err.status)) && count < 2,
      },
      mutations: { retry: false },
    },
  });
}
