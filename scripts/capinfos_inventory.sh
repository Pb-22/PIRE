#!/usr/bin/env bash
set -euo pipefail
for f in /data/incoming/PCAP-BMS-Rerun-April26/*.pcap; do
  echo "=== $(basename "$f") ==="
  capinfos "$f" | egrep "File name|File type|Number of packets|File size|Capture duration|First packet time|Last packet time|Data byte rate|Average packet size"
  echo
done
