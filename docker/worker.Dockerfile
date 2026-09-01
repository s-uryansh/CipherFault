FROM python:3.13-slim

ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_BUILD=20260605
ARG GHIDRA_SHA256=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
ARG PYTORCH_CPU_INDEX_URL=https://download.pytorch.org/whl/cpu

ENV GHIDRA_INSTALL_DIR=/opt/ghidra \
    CIPHERFAULT_RECOGNIZER_MODEL=/app/models/recognizer.pt \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl openjdk-21-jdk-headless unzip \
    && curl -fsSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip" -o /tmp/ghidra.zip \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "$GHIDRA_INSTALL_DIR" \
    && rm -f /tmp/ghidra.zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY models/ models/
COPY scripts/check_deploy_runtime.py scripts/check_deploy_runtime.py
RUN pip install --no-cache-dir --index-url "$PYTORCH_CPU_INDEX_URL" torch \
    && pip install --no-cache-dir ".[api,recognizer]"

CMD ["rq", "worker", "scans", "--url", "redis://redis:6379/0"]
