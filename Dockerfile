FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PECFF_PROTOTYPE_MODE=true

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libpq-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY src/ /app/src/
COPY scripts/ /app/scripts/

RUN pip install --upgrade pip && \
    pip install -e .

# Patch oscrypto 1.3.0 version regex for OpenSSL 3.x compatibility on Debian Bookworm.
# OpenSSL 3.x version strings like "3.0.11" are not matched by the old \d\.\d\.\d regex.
RUN python /app/scripts/patch_oscrypto.py

EXPOSE 8000

CMD ["uvicorn", "pecff.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
