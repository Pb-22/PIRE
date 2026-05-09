# PIRE Working Summary

## If you are just re-entering this project
Start with:
1. `README.md` — now the real operator-facing manual
2. this working summary — latest working state and cautions
3. `docs/runtime-repo-structure.md` and `PIRE-v1-spec.md` only if you need deeper implementation/design context

## Current state in one page
PIRE is now a working PCAP investigation workbench with:
- PCAP upload / load management
- summary and evidence pivots
- Zeek-backed log exploration
- merged / fallback-aware log views
- OpenClaw-backed case chat
- knowledge queue and saved-knowledge editing
- screenshot-backed README sections for the main UI surfaces

Core framing still holds:
- **OpenClaw is the reasoning participant**
- **PIRE is the packet workbench, evidence surface, and pivot engine**

## What changed most recently
### README / GitHub polish
The README was upgraded from notes into a usable operator manual and now includes inline screenshots placed in the relevant UI sections.

Current screenshot paths used by the README:
- `docs/screenshots/ui/sidebar/current-load.png`
- `docs/screenshots/ui/evidence/immediate-attention.png`
- `docs/screenshots/ui/evidence/timeline.png`
- `docs/screenshots/ui/logs/http-merged.png`
- `docs/screenshots/ui/logs/files-merged.png`
- `docs/screenshots/ui/logs/search-feedback.png`
- `docs/screenshots/ui/knowledge/queue.png`
- `docs/screenshots/ui/knowledge/saved-knowledge-editor.png`

Latest pushed README/screenshots commit at summary time:
- `b094e7c` — `Place UI screenshots into README sections`

### UI / workflow shape to preserve
Important current UI areas:
- **Sidebar** — capture inventory, current load, download/delete actions
- **Evidence** — Immediate Attention and Timeline are especially important for first-pass triage
- **Logs** — merged Zeek + packet-derived views matter; do not regress provenance or ordering behavior
- **Knowledge** — Queue is for deliberate review, Saved Knowledge is editable in-place

## Working rules to preserve
- Keep **container-first** validation as the default path.
- Preserve **packet-grounded / frame-grounded** investigation as primary.
- Treat **Zeek as additive**, not a replacement for packet truth.
- Keep the knowledge queue selective; it should not become noisy clutter.
- Prefer reusing local saved knowledge before suggesting broader external lookup.

## Known local repo state
At summary time, the repo had one unrelated local modification outside this work:
- `.gitignore` was locally modified and intentionally not bundled into the README/screenshot commits

Be careful not to accidentally include that change in unrelated follow-up commits unless you explicitly review it.

## Best re-entry path next time
1. Read `README.md` and verify the documented screenshots still match the current UI.
2. Check `git status` for any leftover local-only edits.
3. Re-verify important flows in the intended container/compose path if code changes are planned.
4. Then move directly into the next investigation or detection task.

## Good next work
The user is ready to move on from README/screenshot cleanup and continue with another detection-focused task.
