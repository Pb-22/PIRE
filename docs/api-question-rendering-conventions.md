# PIRE User-Facing API Question Rendering Conventions

## Purpose
These conventions define how PIRE should present candidate API/reference questions to the user so they are understandable, evidence-backed, and easy to select.

## Core rules
- Use a numbered list.
- Keep each question self-contained.
- Ground each question in current-case evidence.
- Distinguish protocol knowledge from experiential knowledge.
- Explain why the question is worth asking.
- Make selection easy with commands like `ask 1`, `ask 1-3`, or `ask 2 then 5`.
- Keep the visible format stable across turns.

## Required render shape
Each proposed question should use this exact visible structure:

1. **Question:** <plain-language question>
   - **Why ask:** <why this reduces uncertainty or improves the investigation>
   - **PCAP evidence:** <frame refs, endpoints, streams, objects, or short observation summary>
   - **Experiential knowledge:** <relevant prior case, detection, heuristic, or `None yet`>
   - **Protocol knowledge:** <relevant durable protocol knowledge or `None yet`>
   - **Helpful answer would:** <what kind of answer would change the next step>

## Evidence rules
### PCAP evidence line
- Prefer frame references when available.
- If frame references are too many, summarize and include the most useful anchors.
- Mention endpoints or streams when they help disambiguate the traffic.
- Keep this line short enough to scan.

Good:
- **PCAP evidence:** Frames 421, 428, 446; OPC UA traffic between 10.10.20.15 and 10.10.20.40.

Bad:
- **PCAP evidence:** A huge paragraph with every observation mixed together.

### Experiential knowledge line
- Reference prior cases, detections, or heuristics when they truly matter.
- If none are relevant yet, say `None yet`.
- Do not smuggle protocol facts into this line.

### Protocol knowledge line
- Reference stable protocol understanding.
- Keep this distinct from case-specific hypotheses.
- If knowledge is thin, say `None yet` or state the narrow known point.

## Ordering rules
When listing multiple questions:
- Put the highest-value or highest-leverage question first.
- Group closely related questions near each other.
- Prefer 3-6 questions at a time.
- If more than 6 are possible, show the best set first and offer more if needed.

## Tone rules
- Sound investigative, not academic.
- Prefer plain English over jargon unless the jargon is the point.
- Be explicit about uncertainty.
- Avoid pretending the API question is necessary if it is merely optional.

## Selection prompt
After presenting questions, end with a short selection cue such as:
- `Say "ask 1" to ask the first question.`
- `Say "ask 1-3" to ask the first three.`
- `Say "ask 2 then 5" to choose a custom order.`

## When not to show numbered questions
Do not force the numbered-question format when:
- the user already clearly asked one precise external question
- the answer can be produced directly from packet evidence without outside help
- no good external question exists yet

In those cases, continue the investigation naturally and only introduce numbered questions when they add real value.

If the user directly says what exact external/API question to ask, acknowledge that and bypass the numbered list cleanly.

## Example render
1. **Question:** Does this OPC UA service pattern align with common normal client/server behavior?
   - **Why ask:** We need to decide whether the repeated service mix looks routine or worth deeper scrutiny.
   - **PCAP evidence:** Frames 421, 428, 446; repeated OPC UA exchanges between 10.10.20.15 and 10.10.20.40.
   - **Experiential knowledge:** None yet.
   - **Protocol knowledge:** OPC UA commonly uses stable client/server exchanges, but we have not yet confirmed whether this service mix is typical.
   - **Helpful answer would:** A short explanation of whether this pattern is common, plus which service types deserve closer review.

2. **Question:** Which OPC UA methods or service types are most worth inspecting for unusual industrial behavior?
   - **Why ask:** Even if the traffic is mostly normal, this helps prioritize where to look next.
   - **PCAP evidence:** Current summary shows repeated session/service exchanges but no confirmed anomaly yet.
   - **Experiential knowledge:** Prior OPC UA anomaly note suggests service selection can matter when behavior looks out of role.
   - **Protocol knowledge:** Some OPC UA operations are more operationally sensitive than others, especially in industrial contexts.
   - **Helpful answer would:** A ranked shortlist of service types or behaviors to examine next in this case.

Selection cue:
`Say "ask 1", "ask 1-2", or "ask 2 then 1".`
