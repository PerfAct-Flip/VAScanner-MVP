FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Nuclei is baked into this image as a pinned, verified binary — same approach
# as the backend's own Dockerfile — so it never depends on the host's PATH.
ARG NUCLEI_VERSION=3.11.1
RUN curl -fsSL -o /tmp/nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -duc -ut  # bake templates into the image so scans don't need network access to GitHub at runtime

COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /uvx /usr/local/bin/

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY presence_agent ./presence_agent
RUN uv sync --frozen

ENV PATH="/app/.venv/bin:${PATH}" \
    NUCLEI_BINARY=/usr/local/bin/nuclei \
    NMAP_BINARY=/usr/bin/nmap \
    STATE_PATH=/data/credentials.json \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]

CMD ["presence-agent"]
