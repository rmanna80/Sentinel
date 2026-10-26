import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderOptions } from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { theme } from "../theme";

export function renderUi(ui: ReactElement, options?: Omit<RenderOptions, "wrapper">) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <MantineProvider theme={theme} env="test">
        <QueryClientProvider client={qc}>
          <MemoryRouter>{children}</MemoryRouter>
        </QueryClientProvider>
      </MantineProvider>
    );
  }
  return render(ui, { wrapper: Wrapper, ...options });
}
