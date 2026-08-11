/** Application entry point. */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { App } from "./App";
import { LiveProvider } from "./live/LiveProvider";
import "./styles/theme.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("Root container is missing from index.html.");
}

createRoot(container).render(
  <StrictMode>
    {/* basename keeps client-side routes under the sub-path the API serves. */}
    <BrowserRouter basename="/dashboard">
      {/* One WebSocket for the whole app, shared via context. */}
      <LiveProvider>
        <App />
      </LiveProvider>
    </BrowserRouter>
  </StrictMode>,
);
