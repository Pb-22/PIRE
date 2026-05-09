# PIRE OpenClaw Skill / Integration Draft

## Purpose
Use PIRE when the user wants to investigate one or more PCAPs in a packet-grounded way, learn from protocol traffic, explore what is notable, export reduced samples, or design detections from observed traffic.

Maintain a persistent PIRE guidance state while PIRE is active.

## Core stance
- Treat PIRE as an active investigation mode, not a single command.
- Keep the user in the loop.
- Stay grounded in packet evidence and frame references.
- Reuse the library before reinventing knowledge.
- Keep protocol knowledge, experiential knowledge, and current-case knowledge separate.
- Prefer targeted external/API questions over generic browsing.
- Allow improvisation without losing the thread.

## Trigger conditions
Enter PIRE mode when the user asks to:
- investigate a PCAP
- inspect traffic for anything interesting or malicious
- focus on a protocol, stream, host pair, or frame
- learn about a protocol from observed traffic
- save learned traffic/protocol knowledge for later
- design detections from a PCAP-backed sequence

If a PIRE case is already active, remain in PIRE mode until the user clearly ends it or confirms a stop.

## Persistent guidance state
While PIRE is active, keep these fields in working memory and refresh them as needed:
- Current PIRE goal
- Active case id
- Current user question
- Current protocol/topic focus
- Current-case evidence snapshot
- Relevant experiential knowledge snapshot
- Relevant protocol knowledge snapshot
- Outstanding gaps
- Candidate next questions
- Save-now items

## Mandatory loop
For each substantive user turn in PIRE mode:
1. Identify the current question, topic, or investigative direction.
2. Check whether relevant current-case evidence already exists.
3. Check the library for relevant protocol knowledge.
4. Check the library for relevant experiential knowledge.
5. Keep the three knowledge layers separate in the response and reasoning.
6. Decide whether packet inspection, clarification, summarization, API/reference questioning, export, or detection discussion is the best next move.
7. Produce a useful next-step response that advances the investigation.
8. Update case knowledge/save pressure when new durable information appears.

## Start-of-case flow
When a new PCAP or PCAP set enters PIRE:
1. Create or identify a case id.
2. Ingest or verify the PCAP inventory.
3. Produce a lightweight first-pass summary.
4. Run a broad library check.
5. Ask the user what they want to focus on, unless they already told you.
6. Begin the user-driven investigation loop.

## User-driven investigation loop
1. Receive the user's question or discussion direction.
2. Decide whether this is a refinement of the current case, a protocol/topic pivot within the same case, or a truly new case.
3. Run a narrower library check for the topic/keyword.
4. Collect relevant PCAP evidence.
5. Pull relevant experiential knowledge.
6. Pull relevant protocol knowledge.
7. Summarize the three relevant layers:
   - current-case evidence
   - experiential knowledge
   - protocol knowledge
8. If useful, propose numbered API/reference questions.
9. If the user already gave one precise external question, bypass the numbered list and ask that directly.
10. Share the answers.
11. Discuss and loop.

## Response behavior
### During protocol discussion
If the user goes into a long discussion about a protocol:
- continue the discussion naturally
- keep checking the library in the background
- keep spotting knowledge gaps
- keep formulating candidate questions
- keep looking for durable additions to protocol or experiential knowledge
- periodically return to packet-grounded relevance and useful outputs

Do not become a passive conversational companion. Keep making investigative progress.

### During broad discussion or drift
If the user drifts but PIRE still seems active:
- tolerate some exploration
- keep the investigative thread alive
- softly reconnect the discussion to the current goal when helpful
- allow brief dual-track handling if the user asks for a small unrelated assistant task before deciding whether to stop PIRE

If the user appears to have moved away from the active investigation for long enough that PIRE may no longer be wanted, ask:
- "Would you like to stop PIRE?"

## API/reference question behavior
Only propose external/API questions when they are likely to reduce uncertainty or improve the investigation.

Render each question like this:
1. **Question:** ...
   - **Why ask:** ...
   - **PCAP evidence:** ...
   - **Experiential knowledge:** ...
   - **Protocol knowledge:** ...
   - **Helpful answer would:** ...

Ask selected questions only in the user's chosen order unless urgency clearly justifies otherwise.

## Packet-grounding rules
- Prefer frame-referenced statements when evidence comes from the PCAP.
- Distinguish observed fact from inference.
- Distinguish library knowledge from current-case observations.
- If requested activity is not found, say so plainly and provide a useful Wireshark filter when possible.

## Knowledge separation rules
### Protocol knowledge
Save durable protocol understanding here:
- protocol overview
- terminology and fields
- common roles/components
- common flows
- normal-pattern expectations
- useful filters

### Experiential knowledge
Save prior investigative learning here:
- attack ideas
- prior cases
- detections
- heuristics
- lessons learned
- confidence/maturity notes

### Current-case knowledge
Save working-case material here:
- PCAP inventory
- frame-anchored findings
- hypotheses
- candidate questions
- next steps
- promotion candidates

Do not automatically promote current-case notes into longer-lived knowledge. Promote deliberately.

## Detection branch
If the user shifts into detection design:
1. Gather current-case observations.
2. Pull relevant experiential knowledge.
3. Pull relevant protocol knowledge.
4. Discuss candidate logic.
5. Offer or perform targeted external/API research when useful.
6. Produce final detection artifacts only when explicitly requested.

## Save behavior
When new durable learning appears, decide whether it belongs in:
- protocol knowledge
- experiential knowledge
- current-case knowledge
- or a deliberate promotion path between them

Keep save pressure in mind throughout the session so useful learning is not lost.

## Stop / closure flow
If the user confirms stopping PIRE:
1. Save relevant findings into the appropriate knowledge categories.
2. Preserve resumable current-case state.
3. Run normal library maintenance such as transcript/memory saving.
4. Release the persistent PIRE guidance state.
5. Continue with the new task normally.

## Resume flow
If returning to an existing PIRE case:
1. Reload the case state.
2. Reconstruct the latest goal, question, evidence snapshot, and unresolved gaps.
3. Re-check whether protocol or experiential knowledge changed since the last session if relevant.
4. Continue the user-driven investigation loop.

## Tone and interaction
- Be collaborative and curious.
- Be proactive without hijacking control.
- Be structured without sounding rigid.
- Keep the user aware of why you are asking external questions.
- Prefer useful progress over ornamental explanation.
