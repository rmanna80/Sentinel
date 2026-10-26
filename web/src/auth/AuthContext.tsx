import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from "react";
import { api, setCsrfToken, setUnauthorizedHandler } from "../api/client";
import type { AuthState } from "../api/types";

export const AUTH_KEY = ["auth", "state"] as const;

interface AuthContextValue {
  state: AuthState;
  /** Store a fresh AuthState (after setup or sign-in) without another round trip. */
  accept: (next: AuthState) => void;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

/** Mode is shown everywhere a person might mistake demo or test data for real data. */
export function useServerMode(): string {
  return useAuth().state.mode;
}

export function fetchAuthState(): Promise<AuthState> {
  return api.get<AuthState>("/api/auth/state");
}

export function AuthProvider({
  children,
  renderSignedOut,
  renderLoading,
  renderError,
}: {
  children: ReactNode;
  renderSignedOut: (state: AuthState) => ReactNode;
  renderLoading: () => ReactNode;
  renderError: (error: unknown, retry: () => void) => ReactNode;
}) {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: AUTH_KEY, queryFn: fetchAuthState, staleTime: 60_000, retry: 1 });
  const state = query.data;

  useEffect(() => {
    setCsrfToken(state?.signed_in ? state.csrf_token : null);
  }, [state]);

  const accept = useCallback(
    (next: AuthState) => {
      setCsrfToken(next.signed_in ? next.csrf_token : null);
      qc.setQueryData(AUTH_KEY, next);
    },
    [qc],
  );

  // Any 401 from the API means the session ended: drop cached data and show the sign-in screen.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrfToken(null);
      const current = qc.getQueryData<AuthState>(AUTH_KEY);
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "auth" });
      qc.setQueryData<AuthState>(AUTH_KEY, {
        needs_setup: false,
        signed_in: false,
        username: null,
        csrf_token: null,
        mode: current?.mode ?? "production",
      });
      void qc.invalidateQueries({ queryKey: AUTH_KEY });
    });
    return () => setUnauthorizedHandler(null);
  }, [qc]);

  const signOut = useCallback(async () => {
    try {
      await api.post<void>("/api/auth/logout", undefined, { ignoreUnauthorized: true });
    } finally {
      setCsrfToken(null);
      qc.clear();
      await qc.invalidateQueries({ queryKey: AUTH_KEY });
    }
  }, [qc]);

  const value = useMemo(() => (state ? { state, accept, signOut } : null), [state, accept, signOut]);

  if (query.isPending) return <>{renderLoading()}</>;
  if (query.isError || !value) return <>{renderError(query.error, () => void query.refetch())}</>;
  return (
    <AuthContext.Provider value={value}>
      {value.state.signed_in ? children : renderSignedOut(value.state)}
    </AuthContext.Provider>
  );
}
