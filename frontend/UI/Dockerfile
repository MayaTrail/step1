# MayaTrail UI production Dockerfile (React + Vite).
# Multi-stage: Node build, then hardened nginx serving the SPA.

# Stage 1: build
FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY . .

# Vite inlines VITE_* variables into the bundle at build time, so the Google
# client id (public, not a secret) must be present here rather than at runtime.
#
# ARG alone is deliberate. A build arg is already visible to RUN, and when it is
# not supplied it stays absent from the environment, so Vite falls back to the
# .env copied in above. Adding `ENV VITE_GOOGLE_CLIENT_ID=$VITE_GOOGLE_CLIENT_ID`
# would define the variable even when empty, and an existing environment
# variable takes precedence over .env, silently blanking the client id.
ARG VITE_GOOGLE_CLIENT_ID
RUN npm run build

# Stage 2: serve
FROM nginx:1.27-alpine

LABEL org.opencontainers.image.title="mayatrail-ui"
LABEL org.opencontainers.image.description="MayaTrail APT Emulation Platform Dashboard UI"
LABEL org.opencontainers.image.authors="admin@mayatrail.tech"
LABEL org.opencontainers.image.source="https://github.com/mayatrail/step1"

# Create a non-root user to run nginx.
RUN addgroup -g 1001 -S nginxgroup && \
    adduser  -u 1001 -S -G nginxgroup -s /sbin/nologin nginxuser

# Remove the default nginx content and config.
RUN rm -rf /usr/share/nginx/html/* && \
    rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf

# Prepare writable directories the non-root user needs at runtime.
RUN mkdir -p /var/cache/nginx /var/log/nginx /tmp/client_temp /tmp/proxy_temp \
             /tmp/fastcgi_temp /tmp/uwsgi_temp /tmp/scgi_temp && \
    chown -R nginxuser:nginxgroup /var/cache/nginx /var/log/nginx /tmp/client_temp \
             /tmp/proxy_temp /tmp/fastcgi_temp /tmp/uwsgi_temp /tmp/scgi_temp && \
    chown -R nginxuser:nginxgroup /usr/share/nginx/html && \
    chown nginxuser:nginxgroup /etc/nginx/nginx.conf && \
    touch /tmp/nginx.pid && chown nginxuser:nginxgroup /tmp/nginx.pid

COPY --from=build --chown=nginxuser:nginxgroup /app/dist/ /usr/share/nginx/html/

USER nginxuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
