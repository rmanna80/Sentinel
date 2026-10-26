import "@fontsource-variable/atkinson-hyperlegible-next";
import "@fontsource-variable/atkinson-hyperlegible-mono";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "./styles/tokens.css";
import "./styles/global.css";

import { localStorageColorSchemeManager, MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createQueryClient } from "./api/queryClient";
import { App } from "./App";
import { theme } from "./theme";

// Same key the pre-paint script (public/theme-init.js) reads.
const colorSchemeManager = localStorageColorSchemeManager({ key: "sentinel-color-scheme" });
const queryClient = createQueryClient();

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");

createRoot(root).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="dark" colorSchemeManager={colorSchemeManager}>
      <Notifications position="bottom-right" limit={4} />
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>,
);
