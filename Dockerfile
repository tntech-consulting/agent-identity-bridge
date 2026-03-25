FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY aib/ ./aib/
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim

LABEL maintainer="thomas.nirennold@live.fr"
LABEL org.opencontainers.image.source="https://github.com/tntech-consulting/agent-identity-bridge"
LABEL org.opencontainers.image.description="AIB Gateway — Portable identity for AI agents"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd -r aib && useradd -r -g aib -d /home/aib -s /sbin/nologin aib
RUN mkdir -p /data/passports /data/keys /data/receipts && chown -R aib:aib /data

COPY --from=builder /install /usr/local

WORKDIR /app
COPY aib/ ./aib/

USER aib

EXPOSE 8420

ENV AIB_SECRET_KEY=change-me-in-production
ENV AIB_STORAGE_PATH=/data/passports
ENV AIB_KEY_PATH=/data/keys
ENV AIB_LOG_LEVEL=INFO

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8420/')" || exit 1

CMD ["uvicorn", "aib.main:app", "--host", "0.0.0.0", "--port", "8420", "--workers", "1"]
