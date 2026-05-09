#!/usr/bin/env bash
set -euo pipefail

export PATH="/opt/zeek/bin:${PATH}"

if [[ "${PIRE_PROMPT_ON_START:-0}" == "1" ]]; then
  cat <<'BANNER'
PIRE container is up.

Suggested first steps:
- Run `pire doctor` to verify tool availability.
- Place PCAPs under /data/incoming or provide an absolute path.
- Use `pire ingest <pcap>` for metadata.
- Use `pire summary <pcap>` for a first pass.
BANNER
fi

exec "$@"
