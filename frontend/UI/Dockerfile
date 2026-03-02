# ══════════════════════════════════════════════════════
#  MayaTrail UI — Production Dockerfile (React + Vite)
#  Multi-stage: Node build → Hardened nginx serving SPA
# ══════════════════════════════════════════════════════

# ── Stage 1: Build ──
FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build

# ── Stage 2: Serve ──
FROM nginx:1.27-alpine

# ── OCI Labels ──
LABEL org.opencontainers.image.title="mayatrail-ui"
LABEL org.opencontainers.image.description="MayaTrail APT Emulation Platform — Dashboard UI"
LABEL org.opencontainers.image.authors="admin@mayatrail.tech"
LABEL org.opencontainers.image.source="https://github.com/mayatrail/step1"

# ── Create non-root user ──
RUN addgroup -g 1001 -S nginxgroup && \
    adduser  -u 1001 -S -G nginxgroup -s /sbin/nologin nginxuser

# ── Remove default nginx content and config ──
RUN rm -rf /usr/share/nginx/html/* && \
    rm -f /etc/nginx/conf.d/default.conf

# ── Copy custom nginx config ──
COPY nginx.conf /etc/nginx/nginx.conf

# ── Prepare writable directories for non-root nginx ──
RUN mkdir -p /var/cache/nginx /var/log/nginx /tmp/client_temp /tmp/proxy_temp \
             /tmp/fastcgi_temp /tmp/uwsgi_temp /tmp/scgi_temp && \
    chown -R nginxuser:nginxgroup /var/cache/nginx /var/log/nginx /tmp/client_temp \
             /tmp/proxy_temp /tmp/fastcgi_temp /tmp/uwsgi_temp /tmp/scgi_temp && \
    chown -R nginxuser:nginxgroup /usr/share/nginx/html && \
    touch /tmp/nginx.pid && chown nginxuser:nginxgroup /tmp/nginx.pid

# ── Copy built SPA from build stage ──
COPY --from=build --chown=nginxuser:nginxgroup /app/dist/ /usr/share/nginx/html/

# ── Switch to non-root user ──
USER nginxuser

# ── Expose unprivileged port ──
EXPOSE 8080

# ── Health check ──
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/health || exit 1

# ── Start nginx in foreground ──
CMD ["nginx", "-g", "daemon off;"]
