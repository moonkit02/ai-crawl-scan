# AI crawl + ZAP active scan in ONE container.
# Mirrors the production auth-scan container
# (az-scanner-api/serverless/scanner/containers/auth-scan) but swaps the static Playwright
# recording replay for a live browser-use crawl. Same model: a browser proxied through
# ZAP:8080 generates the authenticated traffic, then ZAP active-scans it.
FROM ghcr.io/zaproxy/zaproxy:stable

USER root

# Python + a real Chromium. browser-use 0.13 drives a system browser over CDP (not playwright);
# it auto-detects /usr/bin/chromium and adds --no-sandbox in Docker itself.
RUN apt-get update && apt-get install -y \
      python3 python3-venv python3-pip curl \
      chromium fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Python env: browser-use (crawler) + httpx/dotenv (scan client).
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN pip install --upgrade pip && \
    pip install "browser-use[aws,video]>=0.13.8" "httpx>=0.27" "python-dotenv>=1.0"

WORKDIR /app
# Build context is the repo root (build with: docker build -f docker/Dockerfile -t ai-crawl-scan .)
COPY crawl/ ./crawl/
COPY scan/ ./scan/
COPY docker/docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh && \
    mkdir -p resources/recordings && \
    chown -R zap:zap /app /zap

USER zap

# Run params (override with -e). LLM gateway creds (LLM_BASE_URL/LLM_API_KEY/LLM_MODEL) and the
# TARGET_URL come in at runtime via -e / --env-file — never baked into the image.
ENV TARGET_URL="" \
    APP_USER="admin@juice-sh.op" \
    APP_PASS="admin123" \
    NAME="crawl_scan" \
    ATTACK_STRENGTH="MEDIUM" \
    ALERT_THRESHOLD="HIGH" \
    ZAP_THREADS="6"

ENTRYPOINT ["./docker-entrypoint.sh"]
