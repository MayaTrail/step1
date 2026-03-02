# MayaTrail UI — APT Emulation Platform Dashboard

React 18 + Vite + TypeScript + Tailwind CSS 3 dashboard for managing adversary emulations, detection rules, IR playbooks, and guardrails across AWS, Azure, GCP, AI, and Kubernetes platforms.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | React 18 |
| Build Tool | Vite 6 |
| Language | TypeScript |
| Styling | Tailwind CSS 3 + CSS Custom Properties |
| Routing | React Router v6 |
| HTTP Client | Axios |
| Fonts | Outfit, Space Grotesk, JetBrains Mono |
| Container | Docker (multi-stage: Node build + nginx) |

---

## Prerequisites

- **Node.js** >= 18.x
- **npm** >= 9.x
- (Optional) **Docker** for containerized deployment

---

## Quick Start

```bash
cd UI/
npm install
npm run dev
```

Open `http://localhost:5173` in your browser. Log in with demo credentials (see below).

---

## Commands

### Development

```bash
npm run dev                # Start Vite dev server with HMR (port 5173)
npm run build              # TypeScript check + production build to dist/
npm run preview            # Preview production build locally
```

### Type Checking

```bash
npx tsc --noEmit           # Run TypeScript compiler without emitting files
```

### Linting (if configured)

```bash
npm run lint               # Run ESLint
```

---

## Project Structure

```
UI/
├── index.html                    # Vite entry point (theme init + #root)
├── package.json                  # Dependencies and scripts
├── vite.config.ts                # Vite config (SPA mode, proxy, aliases)
├── tsconfig.json                 # TypeScript configuration
├── tailwind.config.ts            # Tailwind theme (colors, fonts, radii)
├── postcss.config.js             # PostCSS with Tailwind plugin
├── Dockerfile                    # Multi-stage build (Node + nginx)
├── nginx.conf                    # Production nginx with SPA fallback
├── src/
│   ├── main.tsx                  # React entry point
│   ├── App.tsx                   # Router + Context providers
│   ├── styles/
│   │   └── globals.css           # Tailwind directives, CSS vars, utilities
│   ├── types/                    # TypeScript interfaces
│   ├── data/                     # Static platform data (typed TS modules)
│   │   └── platforms/            # aws/, azure/, gcp/, ai/, kubernetes/
│   ├── services/                 # API layer (Axios + mock auth/data)
│   ├── context/                  # React Context providers (Auth, Theme, Platform)
│   ├── hooks/                    # Custom hooks (useEmulations, useSearch, etc.)
│   └── components/
│       ├── layout/               # AppLayout, TopNav, Sidebar, Breadcrumb
│       ├── auth/                 # LoginPage, ProtectedRoute, forms
│       ├── dashboard/            # DashboardPage, stats, feature grid
│       ├── emulations/           # List, detail, tabs, badges
│       ├── playbooks/            # PlaybookPage, PlaybookStep
│       ├── detections/           # DetectionsPage, DetectionRule
│       ├── guardrails/           # GuardrailsPage
│       ├── search/               # SearchModal (global search overlay)
│       ├── modals/               # RunEmulationModal
│       └── ui/                   # Shared: CodeBlock, Tag, EmptyState, etc.
├── js/                           # [Legacy] Vanilla JS reference files
├── css/                          # [Legacy] Vanilla CSS reference files
├── platforms/                    # [Legacy] Platform data JS files
├── app.html.legacy               # [Legacy] Old app shell (renamed)
└── login.html.legacy             # [Legacy] Old login page (renamed)
```

---

## Routes

| Path | Page | Auth Required |
|------|------|:---:|
| `/login` | Sign In / Sign Up | No |
| `/` | Dashboard (Home) | Yes |
| `/:platformId/emulations` | Emulations List | Yes |
| `/:platformId/emulations/:id` | Emulation Detail (4 tabs) | Yes |
| `/:platformId/playbooks/:id` | IR Playbook | Yes |
| `/:platformId/detections` | Detection Library | Yes |
| `/:platformId/guardrails` | Guardrails Configuration | Yes |

**Platform IDs**: `aws`, `azure`, `gcp`, `ai`, `kubernetes`

---

## Demo Credentials

| Username / Email | Password | Display Name |
|------------------|----------|-------------|
| `admin@mayatrail.tech` | `mayatrail` | Ayush Pathak |
| `admin` | `admin` | Admin User |
| `demo` | `demo` | Demo User |

A mock **Google SSO** button is available on the login page for quick access.

---

## Authentication

The app uses JWT-based authentication with a mock implementation:

- `authApi.ts` returns `{ token, user }` where token is a base64-encoded JSON payload
- Token stored in `localStorage`, decoded for user info, validated for expiry
- Axios interceptor attaches `Authorization: Bearer <token>` on all API requests
- 401 responses trigger automatic logout + redirect to `/login`

**To connect a real backend**: Change `authApi.ts` and `platformApi.ts` function bodies from mock to actual `api.post(...)` calls. Zero component changes needed.

---

## Theme & Design System

The UI mirrors the `frontend/` landing page design system defined in `frontend/css/custom.css`:

| Token | Value | Usage |
|-------|-------|-------|
| `--danger` | `#ff2244` | Primary accent, buttons, active states |
| `--safe` | `#00e676` | Success states, safe indicators |
| `--accent-blue` | `#00b4d8` | Section eyebrows, secondary accents |
| `--accent-cyan` | `#48e8c8` | Feature card variants, highlights |
| `--surface-deep` | `#07080c` | Page background |
| `--surface-base` | `#0d0f16` | Sidebar, nav background |
| `--surface-card` | `#111420` | Card backgrounds |

**Fonts**: Outfit (display headings), Space Grotesk (body text), JetBrains Mono (code blocks)

Theme toggle (dark/light) is available in the top nav and persists via `localStorage`.

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Open global search |
| `Escape` | Close search / modals |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | (empty) | Base URL for backend API (e.g., `http://localhost:8000`) |

When not set, the Vite dev server proxies `/api` requests to `http://localhost:8000` via the config in `vite.config.ts`.

---

## Docker

### Build & Run

```bash
cd UI/

# Build the production image
docker build -t mayatrail-ui .

# Run the container
docker run -d -p 8080:8080 --name mayatrail-ui mayatrail-ui
```

Open `http://localhost:8080` in your browser. The container serves the dashboard on port **8080**.

### Multi-Stage Build

The `Dockerfile` uses a two-stage process:

1. **Build stage** (`node:18-alpine`): Installs dependencies, runs `npm run build` to produce optimized `dist/` output
2. **Serve stage** (`nginx:1.27-alpine`): Copies `dist/` into nginx with SPA fallback routing, security headers, non-root user

### Security Features

| Practice | Implementation |
|----------|---------------|
| Non-root execution | `nginxuser` (UID 1001) |
| Pinned base image | `nginx:1.27-alpine` |
| Version hiding | `server_tokens off` |
| Security headers | CSP, X-Frame-Options, X-Content-Type-Options |
| Hidden file blocking | `location ~ /\.` returns 403 |
| Health check | `HEALTHCHECK` on `/health` endpoint |
| SPA routing | `try_files $uri $uri/ /index.html` |

### Useful Docker Commands

```bash
# Build
docker build -t mayatrail-ui .

# Run
docker run -d -p 8080:8080 --name mayatrail-ui mayatrail-ui

# Check health
docker inspect --format='{{.State.Health.Status}}' mayatrail-ui

# Verify non-root
docker exec mayatrail-ui whoami        # nginxuser

# Check security headers
curl -sI http://localhost:8080/ | grep -E "X-Frame|X-Content|Server"

# Run with read-only filesystem
docker run -d -p 8080:8080 --read-only --tmpfs /tmp --tmpfs /var/cache/nginx --tmpfs /var/log/nginx mayatrail-ui

# Stop and remove
docker rm -f mayatrail-ui
```

---

## API Integration

The app is API-ready. All data flows through a service layer:

```
Component -> Hook (useEmulations) -> Service (platformApi) -> Axios (api.ts) -> Backend
```

Currently `platformApi.ts` returns static data from `src/data/`. To connect a real backend:

1. Set `VITE_API_BASE_URL` environment variable
2. Update `platformApi.ts` to use `api.get('/api/platforms/${id}/emulations')` instead of static imports
3. Update `authApi.ts` to use `api.post('/auth/login', ...)` instead of mock responses

No changes needed in hooks, components, or context providers.

---

## Build Output

```bash
npm run build
```

Produces an optimized `dist/` directory:
- TypeScript compilation check (0 errors required)
- Tree-shaken JavaScript bundle (~245 KB gzipped)
- Optimized CSS (~28 KB)
- Asset hashing for cache busting

---

*This project creates intentionally vulnerable cloud resources for security testing. Use only in isolated test accounts.*
