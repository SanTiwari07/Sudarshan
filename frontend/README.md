# Frontend — analyst dashboard

React 18 single-page application. It is the analyst's working surface: upload a sample, watch the pipeline, read the case, inspect the evidence behind each finding, question the AI investigator, and export the report.

- Platform overview: [`../README.md`](../README.md)
- UI design notes: [`../docs/dashboard/10_DASHBOARD.md`](../docs/dashboard/10_DASHBOARD.md)

---

## Stack

| Concern | Choice |
| :--- | :--- |
| Framework | React 18.2 with TypeScript 5.2 |
| Build | Vite 5.2, port 5173, `strictPort` |
| Routing | React Router 6.22 |
| Styling | Tailwind CSS 3.4 with a token layer in `src/theme/` |
| Icons | `lucide-react` |
| Markdown | `react-markdown` 10 with `remark-gfm` |
| Tests | Vitest 2.1, Testing Library 16, jsdom 25 |
| Lint | ESLint 8 with `@typescript-eslint` 7 |

---

## Layout

```text
frontend/
├── public/brand/                 # Project logo assets (colour, black, white)
├── logo/                         # Original logo exports
├── src/
│   ├── App.tsx                   # Route table, auth guards, shared case types
│   ├── main.tsx                  # Entry point
│   ├── config.ts                 # API_BASE, auth headers, 401 interceptor, authed download
│   ├── components/
│   │   ├── batch/                # Batch scan page, fleet summary, job rows, progress hook
│   │   ├── discovery/            # URL discovery area
│   │   ├── investigation/        # Case surfaces: verdict, findings, evidence drawers,
│   │   │                         # score ledger, screenshots, VIDE panels, notes
│   │   │   └── scoreInfluence/   # Per-axis score influence detail views
│   │   ├── layout/               # AppShell, AppHeader, AppSidebar
│   │   ├── motion/               # Reduced-motion-aware animation primitives
│   │   ├── threatIntel/          # Intel overview, attribution, IOC registry, similarity
│   │   ├── ui/                   # Badge, Card, DrawerShell, EvidenceSection, primitives
│   │   └── upload/               # Drop zone, pipeline stepper, stage definitions
│   ├── context/                  # AuthContext, AnalysisContext, InvestigationUIContext
│   ├── hooks/                    # useInvestigationModel, useIntelPayload, useResilience,
│   │                             # useRuntimeScreenshots, useCaseLinks, useDialogBehavior
│   ├── layout/navItems.ts        # Workspace navigation definition
│   ├── lib/                      # View models, evidence mappers, routing and copy helpers
│   ├── pages/                    # Route-level views
│   ├── theme/                    # colors, severity, riskTone, typography tokens
│   ├── types/                    # batch and investigation types
│   └── utils/derive.ts
├── Dockerfile                    # node:18-alpine, runs the Vite dev server
├── vite.config.ts
├── vitest.config.ts
├── tailwind.config.js
└── package.json
```

---

## Routes

Defined in [`src/App.tsx`](src/App.tsx). Everything except `/login` is behind `RequireAuth`; `/login` is behind `PublicOnlyRoute` and redirects an already-authenticated visitor back to where they came from.

| Path | Component | Notes |
| :--- | :--- | :--- |
| `/login` | `pages/Login.tsx` | Credential sign-in |
| `/` | `pages/Upload.tsx` | Upload and live pipeline stepper |
| `/case/:sha256` | `pages/FraudCard.tsx` | Case summary: verdict, score gauge, risk influence, recommended action |
| `/case/:sha256/evidence` | `pages/TechnicalView.tsx` | Findings registry, evidence drawers, screenshots, runtime behaviour |
| `/case/:sha256/intel` | `pages/ThreatIntelView.tsx` | Threat correlation, attribution, IOC registry, visual impersonation |
| `/case/:sha256/ask` | `pages/InvestigationChat.tsx` | Grounded AI investigation chat |
| `/history` | `pages/History.tsx` | Case registry |
| `/history/:sha256` | redirect | Forwards to that case's summary |
| `/batch` | `pages/BatchScan.tsx` | Batch queue and controls |
| `/batch/:batch_id` | `pages/BatchDetail.tsx` | Per-batch job list and progress |
| `/fraud-card`, `/technical`, `/threat-intel`, `/chat` | redirect | Legacy case-less paths, forwarded to the active case |
| `*` | redirect | Falls back to `/` |

### Why the SHA is in the URL

The four investigation views used to sit at case-less top-level paths with the active sample held only in React context and `sessionStorage`. A link to `/technical` showed the recipient whatever case *they* had open. Nesting under `/case/:sha256` makes the URL authoritative, so a link to an investigation is a link to that investigation.

The legacy paths are kept indefinitely — they appear in delivered PDF reports and in AI citations emitted before the move, and a broken evidence trail is worse than a redirect. Build every case path through [`src/lib/caseRoutes.ts`](src/lib/caseRoutes.ts) rather than typing it inline.

Route components are lazy-loaded through `lazyWithRetry`, which reloads once on a chunk-load failure (stale hashed asset after a redeploy) before surfacing the error.

---

## API access

[`src/config.ts`](src/config.ts) is the single source of truth for the API origin:

```ts
export const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api/v1';
```

`VITE_API_URL` is set to `http://localhost:8000/api/v1` by `docker-compose.yml`. In the Vite dev server, `/api` is additionally proxied to `http://backend:8000`.

The module also installs a global `fetch` interceptor that routes any `401` (other than from `/auth/login` and `/auth/register`) to the registered handler, so an expired session logs out cleanly instead of rendering an empty view.

Export endpoints require a bearer token, so a plain `<a href>` does not work — the browser will not attach the `Authorization` header. Use `downloadAuthed(url, filename)` from the same module.

---

## State

| Provider | Responsibility |
| :--- | :--- |
| `AuthProvider` | Token lifecycle, `INITIALIZING` / `AUTHENTICATED` / `UNAUTHENTICATED` status, 401 handling |
| `AnalysisProvider` | Active case, `loadCaseByHash`, loading and error state |
| `InvestigationUIProvider` | Drawer, lightbox and panel state within a case |

`useInvestigationModel` composes the case payload into the view model the investigation surfaces render; `useBatchProgress` polls batch job status; `useRuntimeScreenshots` resolves the screenshot manifest.

---

## Development

With the rest of the stack in Docker:

```bash
cd frontend
npm ci
npm run dev          # http://localhost:5173
```

Point it at a backend other than the default with `VITE_API_URL`.

Inside Compose, `./frontend` is bind-mounted and the container runs `npm run dev -- --host`. Chokidar is forced into polling mode (`CHOKIDAR_USEPOLLING=true`, `CHOKIDAR_INTERVAL=300`, mirrored in `vite.config.ts`) because inotify events fail with `EIO` on Windows and WSL2 bind mounts and take the dev server process down with them.

| Script | Purpose |
| :--- | :--- |
| `npm run dev` | Vite dev server |
| `npm run build` | `tsc` then `vite build` |
| `npm run preview` | Serve the production build |
| `npm test` | Vitest, single run |
| `npm run test:watch` | Vitest, watch mode |
| `npm run lint` | ESLint over `.ts` and `.tsx` |

> The bundled image runs the dev server, not a static build. `npm run build` produces `dist/`, but no production web server is configured in this repository.

---

## Tests

Co-located `*.test.tsx` / `*.test.ts` files next to what they cover, plus `src/test/AuthFlowMatrix.test.tsx` for the auth guard matrix. Setup lives in `src/test/setup.ts`.

```bash
npm test
```

Frontend tests are not part of the Python suite and, like it, are developer-run — there is no CI workflow in this repository.

---

## Conventions

- Severity, risk tone and typography come from `src/theme/`. Do not hardcode a risk colour in a component.
- Analyst-facing wording lives in `src/lib/analystCopy.ts`, `verdictCopy.ts` and `findingExplanations.ts` so the same finding reads identically everywhere it appears.
- Motion respects `useReducedMotion`; animated components must degrade to a static state.
- Case links are built with `caseRoutes` / `caseSectionPath`, never string-concatenated.
