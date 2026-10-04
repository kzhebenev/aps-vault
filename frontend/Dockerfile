FROM nginx:alpine
COPY index.html app.css /usr/share/nginx/html/
COPY app.js pages.js boot.js i18n.js i18n-en.js /usr/share/nginx/html/
# The backend address is a variable so the frontend can live next to any backend service name
# (sidecar in another compose project, a load balancer): the image renders the template at start.
ENV VAULT_BACKEND_URL=http://backend:8086
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
# Frontend healthcheck (0.30.1): the vault's own compose and host checks can see a dead nginx.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
