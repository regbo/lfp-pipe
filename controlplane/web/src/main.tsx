import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MantineProvider } from "@mantine/core";
import { ManagementConsole } from "./management-console";
import { appTheme } from "./theme";
import "@fontsource-variable/inter";
import "@mantine/core/styles.css";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MantineProvider theme={appTheme} defaultColorScheme="auto">
      <ManagementConsole />
    </MantineProvider>
  </StrictMode>,
);
