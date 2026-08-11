# Network Defender Dashboard

React + TypeScript SPA for the Network Defender SOC dashboard. See
[ADR 7](../docs/PLAN.md#adr-7-react--typescript--vite-for-the-dashboard) for
why this stack, and [`docs/UI.md`](../docs/UI.md) for screen flows.

## Prerequisites

Node 20+ and npm.

## Development

```bash
npm install
npm run dev          # Vite dev server on :5173, proxying /api and /ws to :8000
```

Run the API alongside it so the proxy has something to talk to:

```bash
uv run uvicorn network_defender.api.app:create_app --factory --reload
```

The dev server proxies `/api` and `/ws` to the API, so the frontend sees the
same origin in development as in production. That matters: a CORS-enabled dev
setup hides same-origin bugs until deployment.

## Build

```bash
npm run build
```

Output goes to `../src/network_defender/api/static/`, where FastAPI serves it
at `/dashboard`. The bundle is **not committed** — it is a build artifact, and
committing it would put a large minified diff in every frontend pull request.
Until it is built, `/dashboard` returns a 503 explaining how to build it.

## Test and lint

```bash
npm test             # Vitest + Testing Library
npm run lint         # oxlint
```

## Layout

| Path | Purpose |
|---|---|
| `src/api/` | Typed REST client and shared API types. |
| `src/components/` | Reusable presentational components. |
| `src/hooks/` | Data fetching, WebSocket and theme hooks. |
| `src/pages/` | One module per route. |
| `src/styles/` | Design tokens and global styles. |

Styling uses CSS Modules with custom properties for theming — no utility
framework, so there is no extra build step or class-name dictionary to learn.
