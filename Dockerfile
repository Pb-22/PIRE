FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/zeek/bin:${PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        bash \
        file \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key \
        | gpg --dearmor -o /etc/apt/keyrings/zeek.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_12/ /" \
        > /etc/apt/sources.list.d/zeek.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        tshark \
        wireshark-common \
        tcpdump \
        jq \
        yq \
        ripgrep \
        zeek \
        zkg \
    && ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek \
    && ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut \
    && ln -sf /opt/zeek/bin/zkg /usr/local/bin/zkg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml requirements.txt README.md ./
COPY src ./src
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
    && python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install .

RUN mkdir -p /data/incoming /data/output /data/exports /data/cache /data/cache/zeek /data/cache/zeek/logs

ENTRYPOINT ["/entrypoint.sh"]
CMD ["pire", "--help"]
