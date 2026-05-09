# Prompting strategy for PIRE

## Short answer
Yes, but the main prompt should live in the OpenClaw skill/integration layer, not only in the container startup path.

## Recommended split

### 1) OpenClaw skill prompt (primary)
This should define:
- what PIRE is for
- how to ingest a PCAP
- how to preserve Wireshark frame fidelity
- how to step through broad investigations and wait for `next`
- how to handle protocol-guided hunts
- how to handle frame pivots
- how to respond when requested activity is not found
- how to avoid premature detection generation

This is the durable behavior layer.

### 2) Container startup banner (secondary, optional)
A startup banner can remind the operator of:
- where to place PCAPs
- which commands to run first
- where outputs land

This is useful for interactive shell sessions but should stay lightweight and optional.

## Current scaffold decision
The current container supports an optional startup banner controlled by:
- `PIRE_PROMPT_ON_START=1`

Default is off.

## Why not make the container prompt mandatory?
Because:
- automation and scripts should not have to parse a banner
- the real behavioral intelligence belongs in the OpenClaw skill
- a container should remain predictable as a runtime substrate

## Future follow-on
Create a dedicated PIRE OpenClaw skill that acts as the true behavioral prompt for analysis sessions.
