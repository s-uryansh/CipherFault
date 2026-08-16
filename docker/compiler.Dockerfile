ARG BASE=debian:bookworm
FROM ${BASE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends git libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
