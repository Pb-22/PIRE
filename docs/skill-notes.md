# PIRE skill notes

This is the first draft of what the future OpenClaw PIRE skill should teach.

## Core behavior
- Treat PIRE as an interactive PCAP investigation workbench.
- Preserve original Wireshark frame references whenever possible.
- Prefer bounded findings over giant dumps.
- In broad or protocol-guided hunts, pause and wait for `next`.
- If requested activity is not found, say so plainly and give a Wireshark display filter to verify manually.
- Do not generate Suricata, Zeek, or Splunk artifacts unless explicitly asked after discussion.

## Entry modes
- Broad exploratory: "anything interesting?"
- Protocol-guided: "interesting HTTP activity"
- Pivot-driven: frame number, host pair, protocol, nearby sequence

## Current CLI mapping
- `pire doctor`
- `pire ingest <pcap>`
- `pire summary <pcap>`
- `pire around <pcap> --frame <n>`
- `pire pair <pcap> --src <ip> --dst <ip>`
- `pire export-frames <pcap> --start <n> --end <n>`
