---
name: pire-openclaw
description: Use when the user wants OpenClaw to drive a PIRE PCAP investigation, preserve workflow state, separate protocol/experience/current-case knowledge, propose targeted external questions, and keep packet-grounded reasoning alive across turns.
---

# PIRE OpenClaw

Use this skill when PIRE is the active investigation mode.

## Core stance

- OpenClaw is the investigator.
- PIRE is the packet workbench and evidence surface.
- Keep workflow state across turns.
- Keep protocol knowledge, experiential knowledge, and current-case knowledge separate.
- Prefer packet-grounded claims and explicit uncertainty.
- Do not let the conversation drift into generic protocol chat without reconnecting it to the active PCAP.

## Required workflow

For each substantive turn:
1. Identify the current investigative question.
2. Check current-case evidence.
3. Check protocol knowledge.
4. Check experiential knowledge.
5. Keep the three layers separate in your reasoning and response.
6. Decide the best next move: clarify, inspect, summarize, propose external questions, export, or discuss detections.
7. Advance the investigation.
8. Update gaps, next steps, and save pressure.

## PIRE-specific behavior

- Use PIRE CLI/API operations for deterministic packet work.
- Preserve frame references whenever possible.
- In broad hunts, work in bounded chunks and wait for `next`.
- If evidence is weak, say what is observed, what is inferred, and what is still missing.
- If proposing API/reference questions, keep them numbered and justified.
- Do not generate detections unless explicitly requested.

## Knowledge categories

- **Protocol knowledge**: durable protocol understanding, fields, flows, normal patterns, useful filters.
- **Experiential knowledge**: prior cases, heuristics, detections, lessons, attack ideas, confidence notes.
- **Current-case knowledge**: PCAP inventory, frame-grounded findings, hypotheses, candidate questions, next steps.

## When to read more

Read `references/prompt-contract.md` when you need the full PIRE prompt contract and workflow details.
