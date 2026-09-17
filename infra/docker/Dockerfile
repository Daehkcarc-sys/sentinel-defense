# Organizer image: evaluator CLI, baseline services, and leaderboard.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 \
    SENTINEL_ROOT=/app PATH="/app/.venv/bin:${PATH}"
# Pin uv to the version that produced uv.lock.
COPY --from=ghcr.io/astral-sh/uv:0.12.6 /uv /usr/local/bin/uv
WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

# Public benchmark data only. Private scenarios are mounted read-only at run time.
COPY policies ./policies
COPY fixtures ./fixtures
COPY scenarios/public ./scenarios/public
COPY scenarios/validation ./scenarios/validation
COPY competition.example.yaml ./

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /data /app/artifacts && chown -R 10001:10001 /data /app/artifacts
USER 10001:10001
ENTRYPOINT ["sentinel"]
CMD ["--help"]
