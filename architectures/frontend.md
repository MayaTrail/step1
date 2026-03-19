# Frontend Architecture

## Overview

MayaTrail's frontend is a single-page application (SPA) built with React, TypeScript, and Vite. It serves as the operational dashboard for the MayaTrail cloud-security simulation platform — users can register, log in, manage Pulumi stacks, trigger attack simulations, view detection rules, and explore MITRE ATT&CK mappings.

The frontend communicates with the Django backend exclusively through REST API calls under the `/api/` prefix. There is no server-side rendering; the entire application runs client-side after the initial HTML/JS load.

---

## Technology Stack

| Component | Technology | Version | Notes |
|---|---|---|---|
| UI Library | React | 18.3.1 | Component-based SPA |
| Language | TypeScript | 5.6.3 | Strict typing throughout |
| Build Tool | Vite | 6.0.3 | HMR in dev, optimised production bundle |
| CSS Framework | Tailwind CSS | 3.4.16 | Utility-first styling + custom design tokens |
| Routing | React Router DOM | 6.28.0 | Client-side routing with nested layouts |
| HTTP Client | Axios | 1.7.9 | API calls with interceptors for JWT auth |
| Fonts | Google Fonts | CDN | Outfit (display), Space Grotesk (body), JetBrains Mono (code) |
| Serving | Nginx | 1.27-alpine | Hardened, non-root, multi-stage Docker image |

**Design Decision — Vite + TypeScript over plain JS:**
The original frontend used plain JavaScript with `React.createElement()` calls loaded via CDN script tags. It was rewritten to use Vite + TypeScript for type safety, proper module system, HMR during development, and production-optimised builds. This also enables proper code splitting and tree-shaking.

---

## Directory Structure

```
frontend/UI/
  index.html                   -- Vite HTML entry point
  package.json                 -- Dependencies and scripts
  package-lock.json            -- Lockfile
  vite.config.ts               -- Vite config (React plugin, path aliases, dev proxy)
  tailwind.config.ts           -- Tailwind theme (custom colors, fonts, animations)
  postcss.config.js            -- PostCSS pipeline (Tailwind + autoprefixer)
  tsconfig.json                -- TypeScript configuration
  Dockerfile                   -- Multi-stage: Node build -> Nginx serving
  nginx.conf                   -- Hardened Nginx config for SPA serving
  .dockerignore                -- Excludes node_modules, dist, .env
  .env                         -- Environment variables (VITE_API_BASE_URL)
  src/
    main.tsx                   -- React root: StrictMode + BrowserRouter + App
    App.tsx                    -- Route definitions + provider nesting
    vite-env.d.ts              -- Vite type declarations
    styles/
      globals.css              -- CSS custom properties, Tailwind directives, base styles
    context/
      AuthContext.tsx           -- Auth state: user, login, signup, logout, googleSSO
      ThemeContext.tsx          -- Dark/light theme toggle, persisted to localStorage
      PlatformContext.tsx       -- Platform selection + data caching (AWS, Azure, GCP, etc.)
    services/
      api.ts                   -- Axios instance with JWT interceptor + 401 handler
      auth.service.ts          -- Login, signup, logout, token storage, Google SSO
      stack.service.ts         -- Stack CRUD + deploy/destroy/refresh/preview API calls
      emulation.service.ts     -- Simulation run triggering + status polling
      platform.service.ts      -- Platform data fetching
    hooks/
      usePlatformData.ts       -- Custom hook for loading and accessing platform data
    types/
      index.ts                 -- Re-exports
      auth.ts                  -- User, LoginRequest, SignupRequest types
      platform.ts              -- PlatformId, Stack, SimulationRun, Emulation, etc.
    data/
      index.ts                 -- Data exports
      platforms/
        index.ts               -- Platform manifest registry
        aws/                   -- AWS-specific emulation data and mappings
    components/
      auth/                    -- LoginPage, ProtectedRoute
      layout/                  -- AppLayout (sidebar + topbar + main content area)
      dashboard/               -- DashboardPage (overview with metrics)
      stacks/                  -- StacksPage (CRUD + deploy/destroy UI)
      emulations/              -- EmulationsListPage, EmulationDetailPage
      playbooks/               -- PlaybookPage (step-by-step incident response)
      detections/              -- DetectionsPage (detection rules display)
      guardrails/              -- GuardrailsPage (scope/schedule configuration)
      profile/                 -- ProfilePage (user settings)
      modals/                  -- Reusable modal components
      ui/                      -- Generic UI primitives (buttons, cards, inputs, etc.)
```

---

## Application Bootstrap

```
main.tsx
  └── StrictMode
      └── BrowserRouter (react-router-dom)
          └── App
              └── ThemeProvider (dark/light mode)
                  └── AuthProvider (JWT auth state)
                      └── PlatformProvider (platform data cache)
                          └── Routes
```

**Provider Order Matters:**
- `ThemeProvider` is outermost (no dependencies)
- `AuthProvider` wraps everything that needs auth state
- `PlatformProvider` depends on auth (API calls need JWT)

---

## Routing

Defined in `App.tsx` using React Router v6 nested routes:

```
/login                              → LoginPage (public)
/                                   → ProtectedRoute wrapper
  └── AppLayout (sidebar + topbar)
      /                             → DashboardPage (index route)
      /me                           → ProfilePage
      /stacks                       → StacksPage
      /:platformId/emulations       → EmulationsListPage
      /:platformId/emulations/:id   → EmulationDetailPage
      /:platformId/playbooks/:id    → PlaybookPage
      /:platformId/detections       → DetectionsPage
      /:platformId/guardrails       → GuardrailsPage
```

**Design Decision — Platform ID as Route Parameter:**
The `:platformId` param (e.g. `aws`, `azure`, `gcp`, `ai`, `k8s`) allows the same component tree to serve multiple cloud platforms. When MayaTrail expands beyond AWS, new platforms are added by creating data entries — no new routes or components needed.

**ProtectedRoute:** Checks for an authenticated user via `useAuth()`. If no user, redirects to `/login`. This wraps all non-login routes.

---

## State Management

MayaTrail uses React Context for all shared state. There is no Redux, Zustand, or other state library. Three contexts provide global state:

### AuthContext

| State | Type | Description |
|---|---|---|
| `user` | `User | null` | Currently authenticated user |
| `loading` | `boolean` | Whether an auth operation is in progress |
| `error` | `string | null` | Last auth error message |

**Methods:** `login(req)`, `signup(req)`, `googleSSO()`, `logout()`, `clearError()`

**Persistence:** User data and JWT token are stored in `localStorage` under `mayatrail_token`. On page reload, the stored user is restored immediately.

### ThemeContext

| State | Type | Description |
|---|---|---|
| `theme` | `'dark' | 'light'` | Current theme |

**Methods:** `toggleTheme()`

**Persistence:** Theme is stored in `localStorage` under `mayatrail_theme`. Defaults to `dark`. Applied via a `data-theme` attribute on `document.documentElement` — Tailwind's `darkMode` config is set to `['class', '[data-theme="dark"]']`.

### PlatformContext

| State | Type | Description |
|---|---|---|
| `activePlatform` | `PlatformId | null` | Currently selected platform |
| `cache` | `Partial<Record<PlatformId, PlatformData>>` | Loaded platform data |

**Methods:** `setActivePlatform(id)`, `loadPlatform(id)` (no-op if cached)

**Design Decision — In-Memory Cache:**
Platform data (emulations, detections, guardrails, playbooks) is loaded once per session and cached in context. This avoids re-fetching on every navigation. The cache is lost on page reload, which is acceptable since the data doesn't change frequently.

---

## API Integration

### Axios Instance (`services/api.ts`)

```typescript
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 15_000,
  headers: { 'Content-Type': 'application/json' },
})
```

**Request Interceptor:** Reads `mayatrail_token` from `localStorage` and attaches `Authorization: Bearer <token>` to every request.

**Response Interceptor:** On 401 responses, clears the stored token and redirects to `/login`. This handles token expiry gracefully — the user is silently logged out and sent to re-authenticate.

### Service Layer

All API calls are organised into service modules:

| Service | Endpoints Called | Purpose |
|---|---|---|
| `auth.service.ts` | `/api/auth/login`, `/api/auth/register`, `/api/auth/me`, `/api/auth/refresh` | Authentication lifecycle |
| `stack.service.ts` | `/api/stacks/`, `/api/stacks/{id}/deploy/`, etc. | Stack CRUD + operations |
| `emulation.service.ts` | `/api/simulations/run/`, `/api/simulations/{id}/`, `/api/simulations/modules/` | Trigger + poll simulations |
| `platform.service.ts` | (local data + `/api/simulations/modules/`) | Platform data resolution |

---

## Type System

TypeScript types mirror the backend models exactly:

```typescript
// Stack (mirrors backend infrastructure.Stack)
interface Stack {
  id: string          // UUID
  name: string        // e.g. "dev-himan10"
  region: string      // e.g. "us-east-1"
  status: StackStatus // 'pending' | 'deploying' | 'ready' | ...
  outputs: Record<string, unknown>
  owner: string
  created_at: string
  updated_at: string
}

// SimulationRun (mirrors backend SimulationRun)
interface SimulationRun {
  id: string
  stack: string       // UUID of the target stack
  module: string      // e.g. "s3_initial_access"
  status: SimulationStatus
  stdout: string
  stderr: string
  triggered_by: string
  started_at: string | null
  completed_at: string | null
  created_at: string
}
```

The `EMULATION_MODULE_MAP` constant maps UI-facing emulation IDs (human-readable strings like `priv-esc-attach-role-policy`) to backend numeric module IDs (1-5). This decouples the UI's naming scheme from the backend's auto-generated IDs.

---

## Styling

### Tailwind CSS Configuration

The project uses Tailwind CSS v3 with a custom design system defined in `tailwind.config.ts`:

**Custom Colours:**

| Token | Value | Usage |
|---|---|---|
| `danger` | `#ff2244` | Attack states, error indicators |
| `safe` | `#00e676` | Protected states, success indicators |
| `accent-blue` | `#00b4d8` | Interactive elements |
| `accent-cyan` | `#48e8c8` | Highlights |

**Theme-Aware Colours (CSS Variables):**

| Token | Resolves To |
|---|---|
| `surface-deep` | `var(--surface-deep)` — deepest background |
| `surface-base` | `var(--surface-base)` — main background |
| `surface-card` | `var(--surface-card)` — card backgrounds |
| `surface-elevated` | `var(--surface-elevated)` — popups, modals |
| `content-primary` | `var(--content-primary)` — main text |
| `content-secondary` | `var(--content-secondary)` — secondary text |
| `border-subtle` | `var(--border-subtle)` — subtle borders |
| `border-active` | `var(--border-active)` — interactive borders |

These CSS variables are defined in `globals.css` and swapped based on the `data-theme` attribute, enabling dark/light mode without Tailwind's class-based dark mode.

**Typography:**
- Display: Outfit (headings, hero text)
- Body: Space Grotesk (paragraphs, UI text)
- Monospace: JetBrains Mono (code blocks, terminal output)

**Animations:**
- `fadeIn` — generic fade-in (0.3s)
- `modalIn` — scale + translate for modals (0.25s)
- `slideUp` — content reveal from below (0.3s)
- `spin` — loading spinners (0.6s infinite)

### Global Styles (`globals.css`)

Contains:
- Tailwind's `@tailwind base`, `@tailwind components`, `@tailwind utilities` directives
- CSS custom property definitions for theme colors (dark + light sets)
- Base reset styles
- Custom utility classes not covered by Tailwind

---

## Component Architecture

### Page Components

| Component | Route | Description |
|---|---|---|
| `LoginPage` | `/login` | Login form with username/password + signup toggle |
| `DashboardPage` | `/` | Overview: metrics cards, recent activity, platform quick-links |
| `ProfilePage` | `/me` | User profile + account settings |
| `StacksPage` | `/stacks` | Stack list + create/deploy/destroy UI with status indicators |
| `EmulationsListPage` | `/:platformId/emulations` | Grid of available attack emulations |
| `EmulationDetailPage` | `/:platformId/emulations/:id` | Attack path, MITRE mappings, references, trigger button |
| `PlaybookPage` | `/:platformId/playbooks/:id` | Step-by-step incident response playbook |
| `DetectionsPage` | `/:platformId/detections` | Detection rules in various formats |
| `GuardrailsPage` | `/:platformId/guardrails` | Scope limits, excluded resources, scheduling |

### Layout Components

- `AppLayout` — Wraps all authenticated pages. Provides:
  - Sidebar navigation with platform icons and links
  - Top bar with user info, theme toggle, and breadcrumbs
  - Main content area where page components render

### Shared UI Components

Located in `components/ui/`:
- Buttons, inputs, cards, badges
- Modal primitives (backdrop, container, close button)
- Loading spinners and skeleton states
- Status badges (colour-coded by stack/simulation status)

---

## Build and Development

### Development

```bash
cd frontend/UI
npm install        # install dependencies (one-time)
npm run dev         # start Vite dev server on http://localhost:3000
```

**Dev Proxy:**
Vite's dev server proxies `/api` requests to `http://localhost:8000` (configured in `vite.config.ts`). This eliminates CORS issues during development when running the frontend and backend as separate processes.

**Path Aliases:**
`@` is aliased to `./src` in both `vite.config.ts` and `tsconfig.json`, allowing imports like `import { useAuth } from '@/context/AuthContext'`.

### Production Build

```bash
npm run build       # tsc -b && vite build → outputs to dist/
```

The production build:
1. Runs TypeScript compiler for type checking
2. Vite bundles, tree-shakes, and minifies the output
3. Output goes to `dist/` directory
4. Hashed filenames for cache busting

---

## Deployment (Docker)

### Dockerfile — Multi-Stage Build

```dockerfile
# Stage 1: Build
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# Stage 2: Serve
FROM nginx:1.27-alpine
# ... non-root user setup, security hardening ...
COPY --from=build --chown=nginxuser:nginxgroup /app/dist/ /usr/share/nginx/html/
USER nginxuser
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
```

**Design Decision — Non-Root Nginx:**
The production image runs Nginx as a non-root user (`nginxuser:1001`). This is a security best practice — if the container is compromised, the attacker has no root privileges. The Nginx PID file and temp directories are placed in `/tmp` (writable by non-root).

### Nginx Configuration (`frontend/UI/nginx.conf`)

| Feature | Configuration |
|---|---|
| Listen port | 8080 (unprivileged) |
| SPA fallback | `try_files $uri $uri/ /index.html` |
| Security headers | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, Content-Security-Policy |
| Static asset caching | CSS/JS: 1 hour, images/fonts: 7 days |
| Health check | `/health` → returns `200 ok` |
| Hidden file blocking | `location ~ /\.` → deny all |
| API passthrough | Returns 502 JSON when running standalone (edge proxy handles this in docker-compose) |

---

## Integration with Backend

```
[Browser] → [Edge Nginx :80] → /api/* → [Django backend :8000]
                              → /*    → [UI Nginx :8080]
```

In docker-compose, the edge Nginx (`nginx.conf` at project root) routes:
- `/api/` and `/admin/` → backend service (Django + Gunicorn)
- Everything else → UI service (this frontend)

The frontend never talks directly to the backend. All traffic goes through the edge proxy, which:
- Handles routing
- Sets security headers (X-Frame-Options, etc.)
- Forwards real client IP via `X-Real-IP` and `X-Forwarded-For`
- Uses Docker DNS (`127.0.0.11`) for service resolution

---

## Integration with Docker

- The frontend runs as the `ui` service in docker-compose.
- Built from `frontend/UI/Dockerfile` with multi-stage Node build + Nginx serve.
- Exposes port 8080 internally (not mapped to host directly — the edge proxy handles external access).
- Health check: `wget -q -O /dev/null http://localhost:8080/health`

---

## Key Conventions

- TypeScript strict mode — all types must be explicit, no `any` unless absolutely necessary.
- Component files use PascalCase (e.g. `DashboardPage.tsx`), service files use kebab-case (e.g. `auth.service.ts`).
- All API communication goes through the `api.ts` Axios instance — never use raw `fetch()` or create separate Axios instances.
- JWT is stored in `localStorage` (not cookies) — acceptable for this application since the CSP prevents XSS attack vectors.
- No SSR — this is a pure client-side SPA. SEO is not a concern (it's an authenticated dashboard).
- `VITE_API_BASE_URL` can override the API base URL; defaults to `/api` (relative, handled by proxy/nginx).

---

## Platform Data Architecture

The frontend supports multiple cloud platforms conceptually:

| Platform ID | Label |
|---|---|
| `aws` | Amazon Web Services |
| `azure` | Microsoft Azure |
| `gcp` | Google Cloud Platform |
| `ai` | AI Security |
| `k8s` | Kubernetes |

Currently, only `aws` has full data (emulations, detections, guardrails, playbooks). Other platforms show placeholder UI. Platform-specific data lives in `src/data/platforms/<platformId>/` and is loaded by `PlatformContext` on demand.

Each platform's data includes:
- **Emulations** — attack scenarios with MITRE ATT&CK mappings, attack paths, severity levels, and origin attributions (Russia, China, NK, Iran, unknown)
- **Detections** — rule definitions in various formats (Sigma, Splunk, etc.)
- **Guardrails** — scope limits, excluded resources, scheduling constraints
- **Playbooks** — step-by-step incident response guides with optional code snippets
