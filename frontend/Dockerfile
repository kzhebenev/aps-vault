FROM nginx:alpine
COPY index.html app.css /usr/share/nginx/html/
COPY app.js pages.js boot.js i18n.js i18n-en.js /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf
