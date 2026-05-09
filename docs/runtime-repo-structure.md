# PIRE Runtime-Facing Repo Structure

This document describes the first concrete runtime-facing structure for PIRE.

## Purpose
The project now has two different kinds of structure:

1. **Design and examples**
   - design notes
   - specs
   - templates
   - example artifacts

2. **Runtime-facing structure**
   - the real `library/` tree PIRE should use for active cases and longer-lived knowledge
   - code helpers that create and maintain that tree

## Runtime tree

```text
library/
  README.md
  protocols/
    README.md
  experience/
    README.md
  cases/
    README.md
    case-index.json
    <case-id>/
      current-case.md
      case-state.json
      knowledge-links.json
      api-answers/
  templates/
    README.md
    protocol-core-template.md
    experiential-note-template.md
    current-case-template.md
```

## Why this shape
- `protocols/` keeps durable protocol knowledge separate from case work.
- `experience/` keeps reusable investigative learning separate from protocol baselines.
- `cases/` holds active and resumable case state.
- `templates/` gives runtime code a predictable place to find the current note skeletons.
- `case-index.json` gives PIRE a simple registry of known cases.

## Code support
The initial runtime helper lives at:
- `src/pire/runtime.py`

It currently provides:
- `ensure_runtime_structure()`
- `bootstrap_case()`
- case-id normalization
- case-index load/save helpers

## CLI support
The CLI now supports:
- `pire init-runtime`
- `pire init-case <case-id>`
- `pire case-show <case-id>`
- `pire retrieve <topic> --case-id <case-id>`
- `pire question-add ...`
- `pire question-select ...`
- `pire question-answer ...`

These commands create the runtime tree, inspect case state, retrieve notes from the three knowledge layers, and persist API-question workflow state.

## Web/UI wiring
The web layer now uses these primitives to:
- auto-create a case for the loaded PCAP
- update `case-state.json` and `current-case.md` during summary, protocol, frame, pair, and export pivots
- retrieve protocol, experiential, and current-case notes during protocol-focused chat turns
- expose case and retrieval data through `/api/case` and `/api/retrieve`
- expose API-question persistence through `/api/questions`, `/api/questions/select`, and `/api/questions/answer`

## Current limits
This is still a thin scaffold.

It does **not** yet implement:
- automatic promotion logic
- richer semantic retrieval or ranking
- direct OpenClaw agent orchestration beyond the shared primitives
- rendered API-answer persistence beyond simple file placement

Those are the next layer above this structure.
