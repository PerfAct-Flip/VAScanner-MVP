# ---- Frontend build ----
FROM oven/bun:1 AS frontend-build

WORKDIR /frontend

COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile

COPY frontend/ ./
RUN bun run build

# ---- Backend ----
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Nuclei is baked into this image as a pinned, verified binary — never resolved
# from the host/PATH — so a broken host package manager (e.g. a corrupt scoop
# shim) can never cause the scanner to invoke a bogus binary again.
ARG NUCLEI_VERSION=3.11.1
RUN curl -fsSL -o /tmp/nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -duc -ut  # bake templates into the image so scans don't need network access to GitHub at runtime

COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /uvx /usr/local/bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY app ./app
COPY alembic.ini ./
COPY migrations ./migrations
COPY --from=frontend-build /frontend/dist ./static

ENV PATH="/app/.venv/bin:${PATH}" \
    NUCLEI_BINARY=/usr/local/bin/nuclei \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Applies any pending migrations before every container start — idempotent
# (alembic tracks what's already applied), so this is safe to run on every
# boot including restarts where nothing changed.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
