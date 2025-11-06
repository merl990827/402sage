# Dockerfile (compatible with Railway/Render)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl git \
 && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . .

# Install python deps (reads pyproject.toml)
RUN python -m pip install --upgrade pip setuptools wheel \
 && pip install "uvicorn[standard]" \
 && pip install .

EXPOSE 8000
ENV PORT=8000

# If your main app is elsewhere, change src.main:app accordingly
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
