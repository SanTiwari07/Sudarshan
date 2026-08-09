FROM ubuntu:24.04

LABEL maintainer="Sudarshan Core Engineering Team"
LABEL description="Sudarshan APK Analysis Engine Microservice"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV APKTOOL_PATH="/usr/local/bin/apktool"
ENV JADX_PATH="/usr/local/bin/jadx"

# 1. Install system dependencies, Java 17, Python 3.12, ADB, and utility tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    python3.12 \
    python3.12-dev \
    python3-pip \
    python3-venv \
    adb \
    zipalign \
    apksigner \
    aapt \
    android-framework-res \
    curl \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set up Python virtual environment or symlink
RUN ln -sf /usr/bin/python3.12 /usr/bin/python

# 2. Install Pinned APKTool v2.10.0
RUN curl -L "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar" -o /usr/local/bin/apktool.jar && \
    echo '#!/bin/sh' > /usr/local/bin/apktool && \
    echo 'exec java -jar /usr/local/bin/apktool.jar "$@"' >> /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar

# 3. Install Pinned JADX CLI v1.5.1
RUN curl -L "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip" -o /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    rm /tmp/jadx.zip && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    chmod +x /opt/jadx/bin/jadx /usr/local/bin/jadx

WORKDIR /app

# 4. Install Python dependencies
# Build context is the REPO ROOT (see docker-compose.yml).
COPY analysis-engine/requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# 4b. Shared analysis layer - the same package the backend installs, so the two
#     services can no longer drift.
COPY shared/ /opt/sudarshan-core/
# Editable so the ./shared bind mount in docker-compose.yml gives the same
# live-reload behaviour the service code already had.
RUN pip install --no-cache-dir --break-system-packages -e /opt/sudarshan-core

# 5. Copy Application Source Code & Entrypoint
COPY analysis-engine/ .
RUN chmod +x /app/entrypoint.sh

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
  CMD curl -f http://localhost:8001/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
