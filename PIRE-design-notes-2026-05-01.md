# PIRE design notes

Date: 2026-05-01
Project: PIRE
Meaning: PCAP Ingest, Read & Evaluate

## Core concept
PIRE is an interactive PCAP investigation workbench for OpenClaw. The user provides a PCAP and PIRE helps ingest, inspect, discuss, and export activity while preserving stable references back to packet/frame numbers as shown in Wireshark.

PIRE is not meant to automatically generate detections from raw traffic without discussion. It should support interactive investigation first, then detection ideation, and only produce Suricata rules, Zeek scripts, or Splunk SPL when explicitly asked after discussion and agreement.

## User goals
- Provide a PCAP and have PIRE "play" it in a meaningful way.
- Note the important pieces of the PCAP.
- Focus on a protocol and what happens before or after an event.
- Refer to activity by packet number/frame number so the user can follow along in Wireshark.
- Discuss detection ideas based on sequences of events involving one or more protocols.
- Keep detection conversations scoped to roughly up to 3-protocol sequence-based detections.
- Use observed network activity to discuss Suricata rules, Zeek scripts, or Splunk SPL in line with the user's documented preferences.
- Cut/export samples from the PCAP, especially packet ranges and reduced slices.
- Share the container/tooling so other OpenClaw users can run it on their own machines.

## Name
PIRE = PCAP Ingest, Read & Evaluate

## Product definition
PIRE should be an OpenClaw-assisted interactive workflow for:
- packet-grounded investigation
- protocol sequence analysis
- frame-referenced discussion
- export/slicing
- detection ideation after human review
- protocol learning and library enrichment from real traffic examples

## Why PIRE is connected to OpenClaw
PIRE is not connected to OpenClaw just for convenience or chat control. The point is that when a PCAP exposes a protocol of interest, such as OPC UA, OpenClaw should be able to use the capture as a starting point to learn more about that protocol, reason about what appears notable in context, and save the resulting knowledge into the library for later reuse. In other words, PIRE should help turn one investigation into durable protocol knowledge and future baseline material, not merely inspect packets in isolation.

## Protocol learning workflow
When PIRE encounters a protocol of interest, the workflow should be:
1. identify the protocol in the actual PCAP
2. extract packet-grounded evidence such as endpoints, ports, objects, service names, methods, timing, and representative frames
3. consult what is already in the library about that protocol before going outward
4. use OpenClaw to fill gaps, interpret terms, and understand what normal or notable behavior might look like
5. when useful, combine the library knowledge and the packet-grounded evidence to query an API or other reference source for targeted clarification rather than generic browsing
6. compare the reference understanding against the observed traffic
7. save the distilled result back into the library in a reusable form

This means the PCAP is both an investigation target and a learning source.

## User-driven investigation and API loop
A good default interaction loop for PIRE should be:
1. ingest the PCAP
2. perform a broad library check
3. let the user provide a question, topic, or general discussion direction
4. perform a narrower library check for that topic or keyword
5. collect the PCAP data relevant to the question
6. pull the relevant experiential knowledge
7. pull the relevant protocol knowledge
8. summarize the current-case evidence plus the relevant knowledge layers
9. propose a numbered list of candidate API/reference questions, each with the packet-grounded evidence and knowledge context that justifies asking it
10. let the user choose the order, for example "ask 1", "ask 1-3", or "ask 1 then 5 then 2"
11. share the API answers
12. discuss the answers with the user
13. loop back into the next user-directed question or discussion

This keeps the human in the loop while still making OpenClaw proactive and structured.

## Detection-design branch
If the conversation shifts from exploration into detection design, the loop can branch:
1. gather the relevant current-case observations
2. pull matching experiential knowledge such as prior detections, lessons, and attack ideas
3. pull the relevant protocol knowledge so the detection remains grounded in how the protocol normally behaves
4. discuss candidate detection logic with the user
5. optionally offer targeted API/reference questions or perform background browsing/research to improve the detection quality
6. return with refined detection options and only produce final artifacts when explicitly requested

## API question template
When PIRE proposes numbered API/reference questions, each question should be structured so the user can see why it exists and what it is grounded in.

Each numbered question should ideally include:
- the question itself
- why we are asking it
- current-case PCAP evidence
- relevant experiential knowledge
- relevant protocol knowledge
- what kind of answer would help next

This is meant to keep API usage precise, explainable, and tied to the investigation rather than drifting into generic protocol discussion.

Suggested render shape:
1. **Question:** ...
   - **Why ask:** ...
   - **PCAP evidence:** ...
   - **Experiential knowledge:** ...
   - **Protocol knowledge:** ...
   - **Helpful answer would:** ...

## Persistent PIRE attitude and prompting logic
While PIRE is running, OpenClaw should keep a background attitude that is both flexible and goal-oriented.

That means:
- allow improvisation and natural discussion
- do not become rigid or repetitive
- but keep silently tracking what is missing, what should be clarified, what knowledge should be checked, and what useful results should be produced next

If the user goes into a long discussion about a protocol, OpenClaw should not simply drift with the conversation. It should keep:
- checking the library for related knowledge
- spotting knowledge gaps
- formulating candidate questions
- looking for ways to improve protocol knowledge, experiential knowledge, or current-case understanding
- returning the conversation toward useful investigative output when appropriate

The system should not fight the user, but it also should not lose the thread.

## Internal PIRE prompt contract
The OpenClaw layer should likely carry an internal standing prompt or guidance block for as long as PIRE is active.

That standing guidance should tell the agent to:
- remember that PIRE is currently active
- keep the current investigative question in view
- track current-case evidence, experiential knowledge, and protocol knowledge separately
- check whether the library already answers part of the question
- identify missing knowledge and candidate next questions
- prefer packet-grounded statements over vague summaries
- look for opportunities to save durable knowledge
- tolerate exploratory conversation without forgetting the investigation
- softly steer back toward useful output when the conversation drifts too far
- ask whether to stop PIRE if the task appears to have ended

A concise internal shape could be:
- **Current PIRE goal:** what are we trying to understand or produce?
- **Current-case evidence:** what does this PCAP or PCAP set show so far?
- **Experiential knowledge:** what prior cases, detections, or lessons matter?
- **Protocol knowledge:** what durable protocol understanding matters?
- **Gaps:** what is still unclear?
- **Candidate next moves:** what should we ask, inspect, or save next?
- **Save pressure:** what deserves to be written down if we stop now?

## Off-track handling and PIRE stop behavior
If the user seems to be moving away from the active PIRE task for long enough that the workflow is no longer clearly active, OpenClaw may ask a soft steering question such as:
- "Would you like to stop PIRE?"

If the user says yes, PIRE should do closure work before moving on:
1. save the current relevant findings into one or more of the three knowledge categories
2. save current-case state in a recoverable way
3. allow normal library functions such as transcript saving and session-memory maintenance to run
4. then exit the PIRE attitude and move on to the new task

## Library-first prompting and reuse
OpenClaw should be prompted to check the library first before treating a protocol as unfamiliar. If protocol knowledge already exists, the agent should reuse it, extend it, and annotate what is newly confirmed or changed by the current PCAP.

The guidance should explicitly push the agent to answer questions like:
- what do we already know about this protocol?
- what experiential knowledge do we already have from earlier captures or investigations?
- what is specific to this current PCAP or PCAP set?
- what appears normal here?
- what appears notable or uncertain here?
- what should be saved for future investigations, and in which knowledge category?

## Knowledge categories should stay separate
The user does not want all learned material mixed together. PIRE should keep at least three distinct knowledge categories:

### 1) Protocol knowledge
This is the more permanent layer. It should capture how a protocol works, its terminology, common message flows, field meanings, common roles, and what normal behavior often looks like.

### 2) Experiential knowledge
This is the accumulated investigative layer. It should capture things like:
- cases where we saw a protocol used in a meaningful way
- current intelligence suggesting an attack may look a certain way on the wire
- detections we built from prior observations
- recurring investigative heuristics
- lessons learned from prior hunts

### 3) Current case knowledge
This is the working memory for the current PCAP or current set of PCAPs. It includes what this exact capture seems to contain, current hypotheses, candidate pivots, and temporary notes that may or may not deserve promotion into the other two categories.

Current case knowledge can feed protocol knowledge or experiential knowledge, but it should not be promoted automatically. Sometimes a PCAP teaches us something durable; sometimes it is just a one-off detail.

## Robust knowledge saving
Knowledge capture should not be a vague note saying "looked at OPC UA." It should save durable artifacts that future OpenClaw sessions can actually use, while preserving the category distinctions above.

Useful saved elements include:
- protocol overview written for future investigations
- observed roles and components in the environment
- representative message types, objects, services, or operations seen
- candidate normal patterns and baseline expectations
- frame-anchored examples from the PCAP
- useful Wireshark and tshark filters
- unresolved questions or follow-up ideas
- links back to the source PCAP or extracted artifacts when practical
- explicit indication of whether a note belongs to protocol knowledge, experiential knowledge, or current case knowledge

## Library structure proposal
A practical first structure for the library side of PIRE could be:

- `library/protocols/<protocol>/`
  - durable protocol notes
  - normal-pattern notes
  - common filters
  - protocol-specific glossary/field notes

- `library/experience/<protocol-or-theme>/`
  - prior cases
  - attack ideas
  - detections built from observations
  - investigative heuristics and lessons learned

- `library/cases/<case-id>/`
  - current-case summary
  - PCAP inventory
  - current hypotheses
  - frame-anchored findings
  - candidate API questions
  - stop/resume state

This structure keeps the three knowledge types separate while still allowing links between them.

## Note templates by knowledge category
Each category should have a different template shape.

### Protocol knowledge template
- protocol name
- concise overview
- terminology / important fields
- common roles and components
- common message flows
- what normal often looks like
- known useful filters
- representative examples
- open questions
- related experiential notes

### Experiential knowledge template
- case or theme name
- why it matters
- observed or hypothesized wire pattern
- related detections or logic
- investigative heuristics
- confidence / maturity
- related protocols
- related case links
- notes on whether the idea is environment-specific or more general

### Current-case knowledge template
- case id / pcap set
- current question or objective
- relevant pcap files
- working summary
- frame-anchored evidence
- current hypotheses
- relevant experiential knowledge links
- relevant protocol knowledge links
- candidate API questions
- next recommended steps
- what should be promoted, if anything

Concrete draft markdown templates are now saved at:
- `/home/claw/.openclaw/workspace/projects/PIRE/templates/protocol-core-template.md`
- `/home/claw/.openclaw/workspace/projects/PIRE/templates/experiential-note-template.md`
- `/home/claw/.openclaw/workspace/projects/PIRE/templates/current-case-template.md`

## Stop/resume state idea
PIRE should keep a resumable state file for an active case.

Useful fields might include:
- active case id
- current user question
- current protocol/topic focus
- relevant pcap files
- latest evidence summary
- latest experiential knowledge references
- latest protocol knowledge references
- outstanding questions
- proposed API questions and which ones were already asked
- save pressure / items at risk of being lost
- last recommended next step

Recommended concrete format:
- `library/cases/<case-id>/case-state.json`
- one JSON document per active case
- append/update friendly rather than transcript-like
- should include case metadata, PCAP inventory, evidence snapshot, knowledge links, API question state, outstanding gaps, promotion candidates, and next-step state

## Library link and promotion format
PIRE should store link/promotion records explicitly rather than relying on loose prose.

A simple first format is a JSON array file such as:
- `library/cases/<case-id>/knowledge-links.json`

Each record could look like:
```json
{
  "link_id": "kl-0001",
  "source_case": "2026-05-02-opcua-bms-rerun-a",
  "source_note": "library/cases/2026-05-02-opcua-bms-rerun-a/current-case.md#L42",
  "target_category": "protocol",
  "target_path": "library/protocols/opcua/core.md",
  "relation": "promote-candidate",
  "reason": "Potentially durable note about normal OPC UA service sequencing.",
  "status": "proposed",
  "created_at": "2026-05-02T18:07:00Z",
  "updated_at": "2026-05-02T18:07:00Z"
}
```

Suggested `relation` values:
- `consulted`
- `supports`
- `contradicts`
- `extends`
- `candidate-relevance`
- `promote-candidate`
- `promoted-to`
- `derived-from`

Suggested `status` values:
- `proposed`
- `accepted`
- `rejected`
- `superseded`

This makes it easier to track how current-case observations become longer-lived knowledge and why.

## Remaining design work queue
We should not lose the follow-on items already identified. At this stage the active design queue includes:
- the internal PIRE prompt/guidance text for the OpenClaw layer
- the library file/note structure for protocol knowledge, experiential knowledge, and current-case knowledge
- note templates for each of those three knowledge categories
- the closure/resume state format for stopping and later resuming PIRE
- eventual skill/integration instructions that encode this behavior durably
- implementation details for turning the draft examples into generated/runtime artifacts

User-facing API question rendering conventions are now drafted at:
- `/home/claw/.openclaw/workspace/projects/PIRE/docs/api-question-rendering-conventions.md`

Illustrative example artifacts are now drafted under:
- `/home/claw/.openclaw/workspace/projects/PIRE/examples/`

## High-level architecture
PIRE should likely have three layers, but the OpenClaw layer should carry persistent guidance state for as long as a PIRE investigation is active:

### 1) CLI analysis engine
A local command-line tool that can ingest, summarize, focus, pivot, and export. Example commands envisioned:
- `pire ingest <pcap>`
- `pire summary <pcap>`
- `pire focus --frame <n>`
- `pire around --frame <n> --before <count> --after <count>`
- `pire proto --name <protocol>`
- `pire pair --src <ip> --dst <ip>`
- `pire export --frames <start>-<end>`
- `pire export --pair <ip1>,<ip2>`

### 2) Docker/container runtime
A portable environment containing packet-analysis tooling and the PIRE scripts so it can run consistently on other OpenClaw hosts.

### 3) OpenClaw skill/integration
A skill or documented integration that teaches OpenClaw what PIRE is for, how to ingest PCAPs, how to step through findings interactively, how to preserve Wireshark frame references, how to handle not-found cases, when to pause for the user to say `next`, and how to consult and enrich the library before and after protocol-specific investigation.

## Core behavior rules

### Interactive first
PIRE should default to interactive stepping for broad/open-ended investigations.
If the user asks something like:
- "do you see anything malicious?"
- "do you see anything interesting?"

PIRE should:
- explain it will inspect in stages
- provide a bounded summary of the current slice/findings
- stop and wait for the user to say `next` before continuing

### Protocol-guided exploratory mode
PIRE should also support a protocol-guided exploratory mode. Example:
- "I'm looking for interesting HTTP activity"
- "Show me suspicious DNS behavior"
- "Anything notable in SMB?"

In this mode, PIRE should:
- limit the investigation lens to the named protocol first
- check what the library already knows about that protocol
- enumerate the activity at a high level
- identify notable requests/responses/objects/metadata/sequences
- cite frame numbers
- distinguish prior knowledge from new observations in this PCAP
- stop after a bounded set of findings
- wait for `next`

If the protocol is absent, PIRE should say so plainly and provide a Wireshark display filter the user can test manually, then ask the user to return with a packet/frame number if they find relevant traffic.

### Event/pivot-driven mode
PIRE should support event-driven pivots such as:
- "look at frame 1842"
- "what happened before and after this Kerberos event?"
- "follow traffic related to this IP pair"

A packet/frame number should be a first-class entry point.

### Preserve frame identity
PIRE should always preserve and expose, where possible:
- original frame number
- timestamp
- source and destination IP
- ports when relevant
- protocol
- stream/conversation identifiers when available

This is essential so the user can follow along in Wireshark.

### Honest not-found behavior
If PIRE does not find the requested activity, it should:
- explicitly say it did not find it
- provide a Wireshark display filter that would locate it if present
- invite the user to manually verify and come back with a packet/frame number if they do find it

### Detection creation is opt-in
PIRE should never jump straight from traffic to final detections by default.
The intended flow is:
1. investigate/observe
2. discuss possible detection logic
3. get user agreement
4. only then create Suricata rules, Zeek scripts, or Splunk SPL if explicitly requested

### Detection scope
The user does not want automatic mass detection creation. The system should support discussion and crafting of detections interactively and only after agreement. Detection logic is expected to focus on sequences involving one or more protocols, often up to about three protocols.

## Large PCAP handling
PCAPs may be large. PIRE should not assume full in-memory loading or giant one-shot JSON exports.
It should instead use a seek-and-index model.

### Minimal first-pass index
On ingest, PIRE should gather lightweight metadata first, such as:
- capinfos summary
- time bounds
- top protocols
- endpoints
- conversations
- stream counts
- lightweight frame index references

Detailed extraction should be performed on demand when the user asks for specific protocols, packet windows, or pivots.

### User-guided stepping for broad hunts
For open-ended hunts in large PCAPs, PIRE should step through findings and continue only after the user says `next`.

## Protocol coverage
The user said protocol interests may vary widely and traffic may not be decrypted. Initial important areas include:
- HTTP
- DNS
- ICMP
- DCE-RPC
- SMB
- Kerberos
- LDAP
- DHCP
- SNMP
- SMTP
- OT/ICS related protocols such as MODBUS, DNP3, BACnet, Profinet, and others

PIRE should therefore be generic by default with first-class helpers for common protocols and graceful metadata-only handling for encrypted traffic.

### Encrypted traffic posture
When traffic is not decrypted, PIRE should rely on metadata and sequence context, such as:
- timing
- endpoints
- ports
- TLS-related metadata where available
- names/cert details where available
- surrounding protocol behavior

It should clearly state when payload visibility is limited.

## Export/slicing requirements
The user emphasized packet-range export first, but also wants the option to reduce noise and cut smaller samples.
Initial export support should include:
- frame/packet range export
- IP-pair conversation export
- all protocols between two IPs
- protocol-specific activity between two IPs
- time-window export
- stream/conversation export where tool support is clean

## Input model
The user would ideally like to attach PCAPs via chat, but regular OpenClaw attachment currently seems geared toward images, so alternatives are needed.

Recommended v1 input approaches:
- file path
- known incoming/drop folder
- SCP into a known incoming directory

Likely practical initial path:
- users place PCAPs in a known directory such as `/home/claw/.openclaw/workspace/pire/incoming/`
- then instruct PIRE to ingest a named file

Chat attachment support can be treated as a later enhancement if OpenClaw supports arbitrary file attachments.

## Portability / sharing with others
The user wants this to be shareable so other OpenClaw users can run it without trouble.
That implies the repo/distribution should include:
- Dockerfile
- docker-compose.yml
- pinned dependency list
- the PIRE CLI/tooling
- an OpenClaw skill or equivalent integration instructions
- documentation for expected mounts, input folders, and invocation patterns
- sample PCAPs and tests if possible

The likely user distribution paths are:
- git clone / git pull from the user's repo
- or SCP of the project files

But simply having the container is not enough; OpenClaw also needs instructions/skill guidance so it understands how to handle incoming PCAPs and what PIRE's purpose and workflow are.

## Tooling considerations
Likely base tooling discussed:
- tshark
- editcap
- mergecap
- capinfos
- tcpdump
- jq
- yq
- ripgrep
- possibly tcpflow / ngrep
- optional zeek
- optional suricata
- optional file / xxd / sqlite3

Likely Python-side needs discussed:
- wrappers around tshark and related CLIs
- possibly pyshark
- scapy for selective tasks
- pydantic
- orjson
- click or typer
- maybe pandas only if genuinely needed
- maybe networkx if relationship graphing becomes useful

Strong bias in the design discussion: main decode path should stay close to tshark/Wireshark behavior so results align with what the user sees in Wireshark.

## Wireshark relationship
Wireshark is the user's follow-along lens, not necessarily the implementation engine itself.
PIRE should use stable frame references so that when it talks about something, the user can jump to the same packet/frame in Wireshark.

## Error-handling expectations
If the user asks for something not found:
- admit it plainly
- provide a Wireshark filter the user can test manually
- ask the user to confirm with a packet/frame number if they do see relevant activity
- continue from that pivot if they return with one

This is especially important for broad or imperfectly decoded protocol hunts.

## User experience / interaction model
Examples of supported user prompts:
- "Do you see anything interesting?"
- "Do you see anything malicious?"
- "I'm looking for interesting HTTP activity"
- "Show me suspicious DNS behavior"
- "Anything notable in SMB?"
- "Look at frame 42018"
- "What happened before and after this Kerberos event?"
- "I'm looking for suspicious Kerberos to LDAP behavior"

PIRE should respond by either:
- stepping through findings in bounded chunks and waiting for `next`
- or directly investigating a specific protocol, IP pair, or frame pivot

## Versioning / scope guidance for v1
The user agreed with a narrow, interactive v1 and specifically does not want automatic detection generation.
V1 should emphasize:
- ingest one pcap at a time
- summarize major activity in a controlled way
- answer frame-number-based questions
- show before/after windows around a frame/event
- support protocol-guided exploratory hunting
- export sub-pcaps by range or conversation/pair
- discuss detection ideas interactively
- produce detections only when explicitly requested after discussion

## Repo naming discussion
The product/tool name should remain PIRE.
A repo name like `pire-openclaw` was considered a reasonable explicit repository name, but no final decision was required yet.

## Immediate next-step idea captured in discussion
A concrete v1 blueprint should eventually be drafted, including:
- repository layout
- docker-compose
- package/dependency list
- CLI command set
- OpenClaw skill behavior
- ingest flow
- export flow
- error-handling rules
- phased milestone plan

## Summary of important added nuance from the user
The user specifically added that they may say something like:
- "I'm looking for interesting HTTP activity"

This protocol-guided exploratory mode is now a required core investigation mode, alongside broad exploratory mode and packet/event pivot mode.
