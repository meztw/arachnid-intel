# ---- Stage 1: Build with Vite ----
FROM node:18-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY index.html vite.config.js ./
COPY src/ src/
RUN npm run build

# ---- Stage 2: Serve with Nginx + data cron ----
FROM nginx:1.25-alpine
RUN apk add --no-cache curl gzip python3
RUN rm -rf /usr/share/nginx/html/*
RUN mkdir -p /var/cache/cve-data
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY scripts/fetch-data.sh /usr/local/bin/fetch-data.sh
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/fetch-data.sh /usr/local/bin/entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
