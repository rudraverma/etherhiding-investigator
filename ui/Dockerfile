# ── Build stage ──────────────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

# ── Serve stage ──────────────────────────────────────────────────────────────
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html

# nginx entrypoint renders /etc/nginx/templates/*.template with envsubst at start.
# kasm-auth.envsh (sourced first) computes KASM_BASIC_AUTH from KASM_PASSWORD, and
# NGINX_ENVSUBST_FILTER limits substitution to that one var so nginx's own
# $variables ($host, $http_upgrade, …) are left intact.
COPY default.conf.template /etc/nginx/templates/default.conf.template
COPY kasm-auth.envsh /docker-entrypoint.d/15-kasm-auth.envsh
RUN chmod +x /docker-entrypoint.d/15-kasm-auth.envsh
ENV NGINX_ENVSUBST_FILTER=KASM_BASIC_AUTH
EXPOSE 80
