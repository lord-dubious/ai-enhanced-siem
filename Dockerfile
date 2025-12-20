# AI-Enhanced SIEM Dockerfile
# Multi-stage build for optimized production image

FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install uv

# Copy dependency files
COPY pyproject.toml requirements.txt ./

# Create virtual environment and install dependencies
RUN uv venv /app/.venv && \
    . /app/.venv/bin/activate && \
    uv pip install -r requirements.txt

# Copy source code
COPY src/ ./src/

# Install the package
RUN . /app/.venv/bin/activate && \
    uv pip install .

# Production stage
FROM python:3.12-slim as production

WORKDIR /app

# Create non-root user for security
RUN groupadd -r siem && useradd -r -g siem siem

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy source code
COPY --from=builder /app/src ./src

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Create directories for logs and data
RUN mkdir -p /app/logs /app/data && \
    chown -R siem:siem /app

# Switch to non-root user
USER siem

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import ai_siem; print('healthy')" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "ai_siem.cli"]
CMD ["--help"]
