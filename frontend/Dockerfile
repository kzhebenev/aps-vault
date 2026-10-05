FROM nginx:alpine
COPY index.html app.css /usr/share/nginx/html/
COPY app.js pages.js boot.js i18n.js i18n-en.js theme.js /usr/share/nginx/html/
# 0.37: patched OS packages (libexpat, pcre2, nghttp2 had fixes the base tag did not carry yet)
RUN apk upgrade --no-cache
# 0.37: the client-certificate fingerprint header is passed to the backend only when an outer TLS proxy sets it and
# the operator says so — otherwise a client could send it itself and satisfy a token's mTLS binding
ENV VAULT_PASS_CERT_FINGERPRINT=0
# The backend address is a variable so the frontend can live next to any backend service name
# (sidecar in another compose project, a load balancer): the image renders the template at start.
ENV VAULT_BACKEND_URL=http://backend:8086
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
# Frontend healthcheck (0.30.1): the vault's own compose and host checks can see a dead nginx.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
