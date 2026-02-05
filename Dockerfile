# Multi-stage build for DeployGuard

# Stage 1: Base image with dependencies
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    openssh-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Stage 2: Development image
FROM base as development

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements-dev.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements-dev.txt

# Copy application code
COPY . .

# Install package in development mode
RUN pip install -e ".[api,dev]"

CMD ["uvicorn", "deployguard.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Stage 3: Production image
FROM base as production

WORKDIR /app

# Copy everything needed for install
COPY requirements.txt .
COPY setup.py .
COPY pyproject.toml .
COPY README.md .
COPY MANIFEST.in .
COPY deployguard ./deployguard
COPY config ./config

# Install Python dependencies and package
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install ".[api]"

# Verify the install worked
RUN python -c "from deployguard.api.app import app; print('API module loaded successfully')"

# Create non-root user
RUN useradd -m -u 1000 deployguard && \
    chown -R deployguard:deployguard /app

USER deployguard

# Note: Health checks are handled by Kubernetes probes

EXPOSE 8000

CMD ["uvicorn", "deployguard.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
