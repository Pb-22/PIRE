# Container notes

## Current image intent

The initial PIRE container packages the core CLI packet-analysis toolchain and a minimal `pire` command.

## Included system packages

- tshark
- wireshark-common
- tcpdump
- jq
- yq
- ripgrep
- file
- bash
- ca-certificates

## Why no Zeek/Suricata yet?

They are intentionally deferred from the very first scaffold so we can validate the core packet-grounded workflow first. They can be added in a later image profile or compose override once the ingest/summary/pivot/export path is proven.

## Prompt on container startup

A startup prompt/banner can be useful, but I would treat it as optional and lightweight.

Recommendation:
- keep startup prompting off by default
- enable it with `PIRE_PROMPT_ON_START=1` when desired
- use the OpenClaw skill as the primary behavioral prompt layer

Reason:
- the durable intelligence about how to use PIRE belongs in the OpenClaw skill/instructions
- the container entrypoint should stay simple and predictable
- a banner is useful for humans in an interactive shell, but should not be the only way the workflow is taught
