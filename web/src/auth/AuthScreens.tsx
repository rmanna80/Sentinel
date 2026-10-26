import { Alert, Anchor, Button, Loader, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { useDocumentTitle } from "@mantine/hooks";
import { IconAlertCircle } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";
import { api, errorMessage } from "../api/client";
import type { AuthState, LoginRequest, SetupRequest } from "../api/types";
import { ModeBadge } from "../layout/ModeBadge";
import { useAuth } from "./AuthContext";
import classes from "./AuthScreens.module.css";

export const MIN_PASSWORD = 12;

function Frame({ children, mode }: { children: ReactNode; mode: string }) {
  return (
    <div className={classes.page}>
      <main className={classes.card}>
        <div className={classes.brand}>
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
            <rect x="3" y="3" width="26" height="26" rx="7" fill="none" stroke="currentColor" strokeWidth="2.5" />
            <rect x="8.5" y="14" width="15" height="4" rx="2" fill="currentColor" />
          </svg>
          <span>Sentinel</span>
          <ModeBadge mode={mode} />
        </div>
        {children}
      </main>
      <p className={classes.foot}>Runs on this computer. Nothing here is sent to the internet.</p>
    </div>
  );
}

export function SignedOut({ state }: { state: AuthState }) {
  return state.needs_setup ? <SetupScreen mode={state.mode} /> : <LoginScreen mode={state.mode} />;
}

export function LoginScreen({ mode }: { mode: string }) {
  useDocumentTitle("Sign in | Sentinel");
  const { accept } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const login = useMutation({
    mutationFn: (body: LoginRequest) =>
      api.post<AuthState>("/api/auth/login", body, { ignoreUnauthorized: true }),
    onSuccess: accept,
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate({ username: username.trim(), password });
  };
  return (
    <Frame mode={mode}>
      <form onSubmit={submit} noValidate>
        <Stack gap="md">
          <Title order={1} size="h2">
            Sign in
          </Title>
          {login.isError ? (
            <Alert color="red" variant="light" icon={<IconAlertCircle size={18} />} role="alert">
              {errorMessage(login.error)}
            </Alert>
          ) : null}
          <TextInput
            label="Username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.currentTarget.value)}
            required
            data-autofocus
            autoFocus
          />
          <PasswordInput
            label="Password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
            required
          />
          <Button type="submit" loading={login.isPending} disabled={!username || !password}>
            Sign in
          </Button>
          <Text size="xs" c="dimmed">
            Forgot the password? On this computer, run <code className="sn-mono">sentinel-server reset-password &lt;username&gt;</code>.
          </Text>
        </Stack>
      </form>
    </Frame>
  );
}

export function passwordIssues(password: string, username: string): string[] {
  const issues: string[] = [];
  if (password.length < MIN_PASSWORD) issues.push(`Use at least ${MIN_PASSWORD} characters (${password.length} so far).`);
  if (username && password.toLowerCase().includes(username.toLowerCase())) issues.push("Don't include the username.");
  if (password && new Set(password).size < 5) issues.push("Use more varied characters.");
  return issues;
}

export function SetupScreen({ mode }: { mode: string }) {
  useDocumentTitle("Set up | Sentinel");
  const { accept } = useAuth();
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState(false);
  const setup = useMutation({
    mutationFn: (body: SetupRequest) => api.post<AuthState>("/api/auth/setup", body, { ignoreUnauthorized: true }),
    onSuccess: accept,
  });
  const issues = passwordIssues(password, username);
  const usernameOk = /^[A-Za-z0-9_.-]{3,64}$/.test(username);
  const mismatch = confirm.length > 0 && confirm !== password;
  const ready = token.trim().length >= 8 && usernameOk && issues.length === 0 && confirm === password;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!ready) return;
    setup.mutate({ setup_token: token.trim(), username, password });
  };

  return (
    <Frame mode={mode}>
      <form onSubmit={submit} noValidate>
        <Stack gap="md">
          <div>
            <Title order={1} size="h2">
              Create your account
            </Title>
            <Text size="sm" c="dimmed" mt={4}>
              This is the only account on this Sentinel server. It controls scans, findings and settings.
            </Text>
          </div>
          {setup.isError ? (
            <Alert color="red" variant="light" icon={<IconAlertCircle size={18} />} role="alert">
              {errorMessage(setup.error)}
            </Alert>
          ) : null}
          <TextInput
            label="Setup token"
            description={
              <>
                Printed in the server console when it started. It's also saved in{" "}
                <span className="sn-mono">setup-token.txt</span> in Sentinel's data folder, and deleted once setup is done.
              </>
            }
            classNames={{ input: "sn-mono" }}
            autoComplete="off"
            spellCheck={false}
            value={token}
            onChange={(e) => setToken(e.currentTarget.value)}
            error={touched && token.trim().length < 8 ? "Paste the token from the server console." : undefined}
            required
            autoFocus
          />
          <TextInput
            label="Username"
            description="Letters, digits, dot, dash or underscore."
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.currentTarget.value)}
            error={touched && !usernameOk ? "Use 3 to 64 letters, digits, dots, dashes or underscores." : undefined}
            required
          />
          <PasswordInput
            label="Password"
            description={`At least ${MIN_PASSWORD} characters. A short sentence works well.`}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
            error={(touched || password.length > 0) && issues.length ? issues.join(" ") : undefined}
            required
          />
          <PasswordInput
            label="Confirm password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.currentTarget.value)}
            error={mismatch ? "The passwords don't match." : undefined}
            required
          />
          <Button type="submit" loading={setup.isPending}>
            Create account
          </Button>
        </Stack>
      </form>
    </Frame>
  );
}

export function AuthLoading() {
  return (
    <div className={classes.page} role="status" aria-live="polite">
      <Loader size="sm" />
    </div>
  );
}

export function AuthError({ error, retry }: { error: unknown; retry: () => void }) {
  return (
    <div className={classes.page}>
      <main className={classes.card}>
        <Stack gap="sm">
          <Title order={1} size="h2">
            Can't reach the Sentinel server
          </Title>
          <Text size="sm">{errorMessage(error)}</Text>
          <Text size="sm" c="dimmed">
            Start it with <code className="sn-mono">scripts\start-server.ps1</code>, then try again. The dashboard lives at{" "}
            <Anchor href="http://127.0.0.1:8765">http://127.0.0.1:8765</Anchor>.
          </Text>
          <Button onClick={retry} variant="default" w="fit-content">
            Try again
          </Button>
        </Stack>
      </main>
    </div>
  );
}
