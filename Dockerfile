# Stage 1: Build virtual environment with uv
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv binary
COPY --from=ghcr.io/astral-sh/uv:0.5.26 /uv /uvx /bin/

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency specifications
COPY pyproject.toml uv.lock ./

# Install dependencies into virtualenv
RUN uv sync --frozen --no-dev --no-install-project

# Copy source code and build project
COPY src/ ./src/
COPY README.md ./
RUN uv sync --frozen --no-dev

# Stage 2: Minimalist distroless-style runtime
FROM python:3.12-slim AS runtime

WORKDIR /app

# Create unprivileged service user
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

# Copy virtualenv and application from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

CMD ["uvicorn", "sentinelshield.main:app", "--host", "0.0.0.0", "--port", "8000"]
