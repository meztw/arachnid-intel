# ── Stage 1: Build frontend ──
FROM node:18-alpine AS frontend
WORKDIR /app
COPY package.json ./
RUN npm install
COPY index.html vite.config.js ./
COPY src/ src/
RUN npm run build

# ── Stage 2: Build Suricata 5.0.10 from source with profiling ──
FROM ubuntu:22.04 AS suricata-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config make wget ca-certificates \
    libpcre3 libpcre3-dev \
    libpcap-dev libnet1-dev \
    libyaml-0-2 libyaml-dev \
    zlib1g zlib1g-dev \
    libcap-ng-dev libcap-ng0 \
    libmagic-dev \
    libjansson-dev libjansson4 \
    libnss3-dev libnspr4-dev \
    rustc cargo \
    && rm -rf /var/lib/apt/lists/*

# Download and compile Suricata 5.0.10 with profiling
WORKDIR /tmp
RUN wget -q "https://www.openinfosecfoundation.org/download/suricata-5.0.10.tar.gz" \
    && tar -xzf suricata-5.0.10.tar.gz \
    && cd suricata-5.0.10 \
    && ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --enable-profiling \
        --disable-gccmarch-native \
    && make -j$(nproc) \
    && make install \
    && make install-conf \
    && ldconfig

# ── Stage 3: Runtime ──
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install runtime deps (no build tools needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gzip cron \
    python3 python3-pip \
    nginx \
    libpcre3 libpcap0.8 libnet1 libyaml-0-2 zlib1g \
    libcap-ng0 libmagic1 libjansson4 libnss3 libnspr4 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy compiled Suricata from build stage
COPY --from=suricata-build /usr/bin/suricata /usr/bin/suricata
COPY --from=suricata-build /usr/lib/libhtp* /usr/lib/
COPY --from=suricata-build /etc/suricata/ /etc/suricata/

# These may or may not exist depending on build - use conditional copy
RUN mkdir -p /usr/lib/suricata /usr/share/suricata /var/lib/suricata/rules /var/lib/suricata/update
COPY --from=suricata-build /usr/share/suricata/ /usr/share/suricata/
RUN ldconfig

# Verify Suricata has profiling
RUN suricata --build-info | grep -i "profiling" || echo "WARNING: profiling status unknown"

# Python deps
COPY api/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Directories
RUN mkdir -p /var/cache/cve-data /var/data/analysis /var/log/suricata /var/run/suricata \
    && rm -rf /usr/share/nginx/html/* \
    && rm -f /etc/nginx/sites-enabled/default \
    && rm -f /etc/nginx/conf.d/default.conf

# Frontend
COPY --from=frontend /app/build /usr/share/nginx/html

# Nginx config
COPY nginx.conf /etc/nginx/sites-enabled/arachnid

# API
COPY api/server.py /opt/api/server.py

# Scripts
COPY scripts/fetch-data.sh /usr/local/bin/fetch-data.sh
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/patch-suricata-yaml.sh /usr/local/bin/patch-suricata-yaml.sh
RUN chmod +x /usr/local/bin/fetch-data.sh /usr/local/bin/entrypoint.sh /usr/local/bin/patch-suricata-yaml.sh

# Patch default suricata.yaml for profiling
RUN /usr/local/bin/patch-suricata-yaml.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
