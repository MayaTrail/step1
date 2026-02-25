# MayaTrail UI Architecture Documentation

This document provides a detailed overview of the frontend architecture, code structure, component breakdown, and runtime instructions for the MayaTrail application UI.

## 1. Structure of the Code

The `UI` folder is organized cleanly into domains separating layout, styles, logic, and mock data APIs:

```text
UI/
├── app.html              # Main application shell (SPA wrapper)
├── login.html            # Authentication gateway (sign-in + sign-up)
├── mayatrail_ui.html     # Monolithic structural design reference
├── Dockerfile            # Production Docker image (hardened nginx)
├── nginx.conf            # Security-hardened nginx configuration
├── .dockerignore         # Docker build context exclusions
├── css/                  # Stylesheets for presentation
│   ├── app.css           # Global layout & component styles (dark + light theme)
│   ├── custom.css        # Specific custom overrides & utilities
│   └── login.css         # Dedicated styling for the login/signup layout
├── js/                   # Core Logic Scripts
│   ├── app.js            # Main controller (routing, state, events, theme toggle)
│   ├── auth.js           # Authentication, signup & session management
│   └── renderer.js       # Dynamic template rendering engine
└── platforms/            # Data Layer (Mock API payloads)
    ├── ai/               # AI platform data (detections, emulations, playbooks)
    ├── aws/              # AWS platform data
    ├── azure/            # Azure platform data
    ├── gcp/              # GCP platform data
    └── kubernetes/       # K8s platform data
```

## 2. Components Used

MayaTrail's frontend is intentionally lightweight, robust, and dependency-free.
* **Markup**: Vanilla HTML5 defining semantic structure.
* **Styling**: Vanilla CSS3 utilizing extensive custom properties (CSS variables) to support dynamic theming, fluid layouts, and responsive design systems.
* **Logic Framework**: Pure Vanilla JavaScript (ES5/ES6) is used across all `.js` files. No heavy frontend compilation frameworks such as React, Angular, or Vue are used.
* **Typography**: Imported web-fonts from Google Fonts (`Space Mono` for data presentation, and `Syne` for headings).

## 3. What Each Component Does

### Views (`.html`)
* **`app.html`**: The main Single Page Application (SPA) container. Defines the persistent layout scaffolding including the top navigation bar, the sidebar platform menu, search modal overlays, and a `#mainContent` dynamic container where internal views are injected.
* **`login.html`**: The authentication page displaying the login interface, SSO buttons, and marketing highlights. Redirects to `app.html` upon successful authentication.

### Logic & Controllers (`js/`)
* **`app.js`**: The main application controller. It initializes the app on DOM load, handles sidebar routing states (`showScreen`), manages search functionality (`filterSearch`), and listens for global UI interactions like opening modals, dropdowns, and keyboard shortcuts.
* **`auth.js`**: Controls client-side authentication and user registration. Validates credentials against both built-in demo users and dynamically registered users stored in `localStorage`. Creates temporary secure sessions (24-hour TTL) and handles protective routing so unauthenticated users cannot access the `app.html` pages directly. Also exposes the signup flow for new user registration.
* **`renderer.js`**: The View rendering engine. Exposes methods like `renderDashboard()`, `renderEmulationsList()`, and `renderPlaybook()` that accept data inputs and programmatically return large HTML string templates containing the final composed DOM.

### Data Layer (`platforms/`)
* **Platform Data Scripts (`detections.js`, `emulations.js`, `playbooks.js`)**: These scripts serve as a mock backend dataset. Upon loading, they dynamically populate the global `window.MayaTrail.platforms` context object with JSON-like dictionary payloads defining adversary techniques, descriptions, and rules for their respective platforms.

## 4. High-Level Design (HLD)

The application follows a **Vanilla SPA (Single Page Application)** architectural pattern.

1. **Initialization:** When `app.html` loads, it sequentially pulls CSS and then invokes the data layer scripts (`platforms/*`), appending everything into `window.MayaTrail`.
2. **Authentication Flow:** `auth.js` validates browser session storage. If active, it resolves; if missing, it redirects to `login.html`.
3. **Application State:** App state is managed globally through runtime variables in `app.js` (e.g., `currentPlatform`, `currentSection`).
4. **Rendering Cycle:** 
    * User interacts with an element (e.g., clicks "AWS APT Emulations" in the sidebar).
    * `app.js` updates global tracking pointers.
    * `app.js` invokes specific mapping functions internally on `renderer.js` (e.g., `MayaTrailRenderer.renderEmulationsList('aws')`).
    * `renderer.js` traverses data pulled from `window.MayaTrail.platforms['aws']`, crafts stringified HTML markup, and returns it.
    * `app.js` assigns the emitted HTML to `document.getElementById('mainContent').innerHTML`, refreshing the primary screen instantly without page reloads.

## 5. How to Deploy or Run the Code

Since the application uses a strict Vanilla JS / HTML approach without any external node module prerequisites or build pipelines (like Webpack/Vite), it can be run out of the box using any static file server.

### Prerequisites
A local HTTP Web Server is required to gracefully serve `.js` script tags and avoid strict Cross-Origin Request parameters enforced on raw `file://` protocols by modern browsers.

### Running Locally
1. Navigate to the `UI` directory in your terminal.
2. Boot up a local static web server. You can use any of the below generic tools depending on your environment:
   * **Node.js**: `npx serve .` — or — `npx http-server`
   * **Python 3**: `python -m http.server 8000`
   * **PHP**: `php -S localhost:8000`
3. Open your browser and navigate to the exposed local address (e.g., `http://localhost:8000/login.html`).
4. Log in using any of the active test user credentials located in `js/auth.js` (e.g., Use `admin@mayatrail.tech` and password `mayatrail`).

### Deployment
This frontend can be seamlessly hosted onto static delivery platforms like **Vercel**, **GitHub Pages**, **Netlify**, or **AWS S3** by simply dropping the contents of the `UI/` folder directly into the host's standard root directory. No build configuration strings are required.

---

## 6. Demo Credentials

The following test accounts are available out-of-the-box for immediate access:

| Username / Email          | Password     | Display Name   |
|---------------------------|-------------|----------------|
| `admin@mayatrail.tech`    | `mayatrail` | Ayush Pathak   |
| `admin`                   | `admin`     | Admin User     |
| `demo`                    | `demo`      | Demo User      |

A mock **Google SSO** button is also available on the login page, which creates a session as `admin@mayatrail.tech` without requiring credentials.

---

## 7. Signup Feature

### Overview
New users can create an account directly from the login page via a **Sign In / Sign Up** tab switcher. Registered accounts are persisted in the browser's `localStorage` and are available for login immediately after creation.

### How It Works

1. **Tab Switcher**: The login page (`login.html`) displays two tabs at the top of the authentication card:  **Sign In** (default, active) and **Sign Up**. Clicking a tab toggles the visible form while hiding the other.

2. **Signup Form Fields**:
   - **Full Name** (required) — Used to generate display name and avatar initials.
   - **Email** (required) — Serves as the username/login identifier. Must be a valid email format.
   - **Password** (required) — Minimum 6 characters.
   - **Confirm Password** (required) — Must match the password field.

3. **Signup Flow** (`auth.js`):
   ```
   User submits form
     → handleSignup() validates all fields (empty checks, password match)
     → MayaTrailAuth.signup(name, email, password) is called
       → Checks email against built-in demo users (prevents duplicates)
       → Checks email against previously registered users in localStorage
       → If unique: generates initials from name, stores user in localStorage
       → Auto-creates a session and redirects to app.html
   ```

4. **Storage Structure**: Registered users are stored under the `mayatrail_users` key in `localStorage` as a JSON array:
   ```json
   [
     {
       "username": "jane@company.com",
       "password": "securepass",
       "name": "Jane Doe",
       "initials": "JD"
     }
   ]
   ```

5. **Login Integration**: The `login()` function checks credentials against both the hardcoded `DEMO_USERS` array and the `mayatrail_users` localStorage array, so registered users can sign back in after their session expires.

### Key Files
| File | Role |
|------|------|
| `login.html` | Contains both Sign In and Sign Up form HTML, tab switcher buttons |
| `js/auth.js` | `signup()` function (validation, storage, session), `handleSignup()` form handler, `switchAuthTab()` UI toggle |
| `css/login.css` | `.auth-tabs` and `.auth-tab` styling for the tab switcher |

---

## 8. Docker

### Quick Start

```bash
cd UI/
docker build -t mayatrail-ui .
docker run -d -p 8080:8080 --name mayatrail-ui mayatrail-ui
```

Open `http://localhost:8080` in your browser. The container serves the dashboard on port **8080**.

### Dockerfile Breakdown

The Dockerfile produces a production-grade, security-hardened nginx container for serving the static UI assets. Below is a walkthrough of each component:

#### Base Image
```dockerfile
FROM nginx:1.27-alpine
```
Uses a **pinned version** of nginx on Alpine Linux. Alpine is chosen for its minimal footprint (~7 MB base) which reduces the attack surface significantly compared to Debian-based images. The version is pinned (not `latest`) to ensure reproducible builds.

#### OCI Labels
```dockerfile
LABEL org.opencontainers.image.title="mayatrail-ui"
LABEL org.opencontainers.image.description="MayaTrail APT Emulation Platform — Dashboard UI"
LABEL org.opencontainers.image.authors="admin@mayatrail.tech"
```
Standard OCI metadata labels for image identification, authorship, and source tracking. These are visible via `docker inspect`.

#### Non-Root User Creation
```dockerfile
RUN addgroup -g 1001 -S nginxgroup && \
    adduser  -u 1001 -S -G nginxgroup -s /sbin/nologin nginxuser
```
Creates a dedicated system user (`nginxuser`, UID 1001) with no login shell (`/sbin/nologin`). The container never runs as root, which is a critical security practice: even if an attacker exploits a vulnerability in nginx, they gain only unprivileged access.

#### Default Content Removal
```dockerfile
RUN rm -rf /usr/share/nginx/html/* && \
    rm -f /etc/nginx/conf.d/default.conf
```
Strips the default nginx welcome page and default server config. This prevents accidental exposure of default content and ensures only our custom configuration is active.

#### Custom Nginx Config
```dockerfile
COPY nginx.conf /etc/nginx/nginx.conf
```
Replaces the entire nginx config with our hardened version (`nginx.conf`), which includes:
- **`server_tokens off`** — hides nginx version from HTTP response headers
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy`
- **Port 8080** — unprivileged port (ports below 1024 require root)
- **Hidden file blocking** — denies access to `.git`, `.env`, `.dockerignore`, etc.
- **`/health` endpoint** — returns HTTP 200 for container orchestrator health checks
- **PID and temp paths in `/tmp/`** — writable locations for the non-root user

#### Writable Directory Preparation
```dockerfile
RUN mkdir -p /var/cache/nginx /var/log/nginx /tmp/client_temp ... && \
    chown -R nginxuser:nginxgroup ...
```
Nginx requires write access to cache, log, and temporary upload directories at runtime. These are explicitly created and ownership is transferred to `nginxuser`. This allows the container to run with a read-only root filesystem if desired (e.g., `docker run --read-only`).

#### Static Asset Copy
```dockerfile
COPY --chown=nginxuser:nginxgroup app.html      /usr/share/nginx/html/
COPY --chown=nginxuser:nginxgroup login.html     /usr/share/nginx/html/
COPY --chown=nginxuser:nginxgroup css/           /usr/share/nginx/html/css/
COPY --chown=nginxuser:nginxgroup js/            /usr/share/nginx/html/js/
COPY --chown=nginxuser:nginxgroup platforms/     /usr/share/nginx/html/platforms/
```
Copies only the required static files into the image, each owned by the non-root user. Explicit per-directory COPY (rather than `COPY . .`) ensures no stray files (README, Dockerfile, monolithic reference HTML) end up in the served directory. The `.dockerignore` provides an additional exclusion layer.

#### User Switch
```dockerfile
USER nginxuser
```
All subsequent commands and the container entrypoint run as `nginxuser` (UID 1001). This is the final security gate, no process in the container ever executes as root.

#### Health Check
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --spider http://localhost:8080/health || exit 1
```
Defines an in-container health probe that hits the `/health` endpoint every 30 seconds. Container orchestrators (Docker Compose, Kubernetes, ECS) use this to determine readiness and trigger restarts on failure.

#### Entrypoint
```dockerfile
CMD ["nginx", "-g", "daemon off;"]
```
Runs nginx in the foreground so Docker can capture stdout/stderr logs and manage the process lifecycle correctly.

### Security Practices Summary

| Practice | Implementation |
|----------|---------------|
| Non-root execution | `nginxuser` (UID 1001), `USER` directive |
| Pinned base image | `nginx:1.27-alpine`, not `latest` |
| Minimal base | Alpine Linux (~7 MB attack surface) |
| Version hiding | `server_tokens off` in nginx.conf |
| Security headers | CSP, X-Frame-Options, X-Content-Type-Options, etc. |
| Hidden file blocking | `location ~ /\.` returns 403 |
| No default content | Default nginx HTML and config removed |
| Health check | Built-in `HEALTHCHECK` on `/health` endpoint |
| Build context control | `.dockerignore` excludes docs, Dockerfile, `.git/` |
| Read-only FS compatible | Writable dirs scoped to `/tmp/` and `/var/cache/` |

### Useful Commands

```bash
# Build the image
docker build -t mayatrail-ui .

# Run the container
docker run -d -p 8080:8080 --name mayatrail-ui mayatrail-ui

# Verify non-root execution
docker exec mayatrail-ui whoami        # → nginxuser
docker exec mayatrail-ui id            # → uid=1001(nginxuser) gid=1001(nginxgroup)

# Check security headers
curl -sI http://localhost:8080/login.html | grep -E "X-Frame|X-Content|Server"

# View container health status
docker inspect --format='{{.State.Health.Status}}' mayatrail-ui

# Run with read-only filesystem (advanced)
docker run -d -p 8080:8080 --read-only --tmpfs /tmp --tmpfs /var/cache/nginx --tmpfs /var/log/nginx mayatrail-ui

# Stop and remove
docker rm -f mayatrail-ui
```
