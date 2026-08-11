FROM python:3.11-slim

WORKDIR /app

# ── System deps ───────────────────────────────────────────────────────────────
# Download adb directly from Google's official platform-tools.
# The Debian apt package 'android-sdk-platform-tools' is unreliable on slim
# images. The Google binary zip is the authoritative source and always works.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        unzip \
        aapt \
        tesseract-ocr \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL \
        "https://dl.google.com/android/repository/platform-tools-latest-linux.zip" \
        -o /tmp/platform-tools.zip \
    && unzip -q /tmp/platform-tools.zip -d /opt/ \
    && rm /tmp/platform-tools.zip \
    && ln -s /opt/platform-tools/adb /usr/local/bin/adb

# Pip defaults for slow or flaky networks (common during Docker Desktop builds).
ENV PIP_DEFAULT_TIMEOUT=300 \
    PIP_RETRIES=15 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ── Python dependencies ───────────────────────────────────────────────────────
# requirements.txt already includes: frida frida-tools
# Build context is the REPO ROOT (see docker-compose.yml) so the shared
# sudarshan-core package can be installed. Paths below are repo-relative.
#
# Install the large Frida wheels in their own layer first so a later transient
# PyPI/DNS failure does not force re-downloading ~33 MB on every retry.
RUN pip install --no-cache-dir \
    frida==17.16.4 \
    frida-tools==14.10.4

COPY backend/requirements.txt .
RUN set -e; \
    for attempt in 1 2 3 4 5; do \
        pip install --no-cache-dir -r requirements.txt && exit 0; \
        echo "pip install attempt ${attempt} failed; retrying in $((attempt * 15))s..."; \
        sleep $((attempt * 15)); \
    done; \
    echo "pip install failed after 5 attempts"; \
    exit 1

# Shared analysis layer - one source of truth for both services.
COPY shared/ /opt/sudarshan-core/
# Editable so the ./shared bind mount in docker-compose.yml gives the same
# live-reload behaviour the service code already had.
RUN pip install --no-cache-dir -e /opt/sudarshan-core

COPY backend/ .

CMD ["sh", "-c", "find /app -name '*.pyc' -delete -o -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null; exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
