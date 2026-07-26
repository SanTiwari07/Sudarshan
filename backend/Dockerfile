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

# ── Python dependencies ───────────────────────────────────────────────────────
# requirements.txt already includes: frida frida-tools
# Build context is the REPO ROOT (see docker-compose.yml) so the shared
# sudarshan-core package can be installed. Paths below are repo-relative.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Shared analysis layer — one source of truth for both services.
COPY shared/ /opt/sudarshan-core/
# Editable so the ./shared bind mount in docker-compose.yml gives the same
# live-reload behaviour the service code already had.
RUN pip install --no-cache-dir -e /opt/sudarshan-core

COPY backend/ .

CMD ["sh", "-c", "find /app -name '*.pyc' -delete -o -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null; exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
