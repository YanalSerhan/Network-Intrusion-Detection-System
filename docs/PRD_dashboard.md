# PRD: Dashboard UX & Data Flow

## Overview
A web-based UI for SOC analysts to view real-time traffic statistics and security alerts.

## Requirements
- **Data Flow:** The frontend communicates with the FastAPI backend via REST (for historical data and config) and WebSockets (for live alert streaming).
- **Views:**
  - **Overview:** Live PPS chart, recent critical alerts, top talkers.
  - **Alerts Log:** Searchable, filterable table of all alerts.
  - **Alert Detail:** Deep dive into a specific alert, showing trigger reason, packet hex dump, and Threat Intel enrichment data.
- **UX Standards:** Responsive design, dark mode support, color-coded severities.
- **Tech Stack:** Modern, lightweight framework (React, Vue, or Vanilla JS with Tailwind) to be defined in an ADR.

## Edge Cases
- Handling alert storms: The UI must gracefully handle bursts of thousands of alerts (e.g., virtualized lists or server-side pagination) without freezing the browser.
