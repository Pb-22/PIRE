# Protocol Knowledge: OPC UA

- **Protocol:** OPC UA
- **Status:** draft
- **Last updated:** 2026-05-02T18:56:00Z
- **Maintainer / source:** PIRE / OpenClaw
- **Related experiential notes:** ../../experience/opcua/opcua-anomaly-001.md
- **Related case notes:** ../../cases/2026-05-02-opcua-bms-rerun-a/current-case.md

## Overview
OPC UA is an industrial communication protocol used for structured data exchange between clients and servers, often in automation and building/industrial environments.

## Why this matters in investigations
OPC UA may appear benign in industrial networks, but understanding normal service usage, roles, and timing helps distinguish routine operations from unusual or risky behavior.

## Terminology and important fields
- **Client / Server:** The typical endpoint roles in OPC UA exchanges.
- **Service:** A request/response operation used to interact with the OPC UA server.
- **Session:** A longer-lived logical interaction that may include repeated service exchanges.

## Common roles and components
- **Engineering workstation / client:** Often initiates management or data-access traffic.
- **OPC UA server:** Exposes data or services to clients.

## Common flows / behaviors
1. **Session establishment and use**
   - Purpose: Create and maintain a usable client/server interaction.
   - Typical sequence: Client connects, negotiates, then issues repeated service requests.
   - Notes: Stable endpoint pairs and repeated service exchanges may be normal.

2. **Routine service polling or reads**
   - Purpose: Retrieve operational data.
   - Typical sequence: Repeated request/response pattern over an established relationship.
   - Notes: Frequency and object selection may matter when evaluating normality.

## What normal often looks like
- Stable client/server endpoint pairs.
- Repeated service exchanges within an established session.
- Behavior aligned with the role of the engineering workstation or control component.

## What may be notable or worth scrutiny
- Service usage that seems out of role for the client.
- Unusual endpoint pairing or unexpected new talkers.
- Service timing or object access patterns that diverge from the local baseline.

## Useful Wireshark / tshark filters
- `opcua` — Isolate OPC UA traffic.
- `ip.addr == 10.10.20.15 && ip.addr == 10.10.20.40 && opcua` — Follow one observed pair.
- `frame.number >= 421 && frame.number <= 446` — Review a known relevant window.

## Representative examples
- **Case / source:** ../../cases/2026-05-02-opcua-bms-rerun-a/current-case.md
  - Frames / evidence: 421, 428, 446, 512.
  - Why it matters: Useful starting point for normal-vs-notable interpretation.

## Baseline notes
- Local baseline knowledge for this environment is still immature.
- Repeated OPC UA service exchanges are present in the sample case and may represent routine behavior.

## Open questions
- Which observed service types in this environment are routine versus unusual?
- What normal polling or management cadence should we expect for this system?

## Promotion / provenance notes
- Derived from: ../../cases/2026-05-02-opcua-bms-rerun-a/current-case.md
- Confidence: medium
- Last substantive change reason: Initial example note created from PIRE design work.
