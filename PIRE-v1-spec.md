# PIRE v1 Specification

Date: 2026-05-01
Project: PIRE
Meaning: PCAP Ingest, Read & Evaluate
Status: Draft v1 specification

## 1. Purpose
PIRE is an interactive PCAP investigation workbench for OpenClaw.

Its job is to help a user:
- ingest a PCAP
- read it in a packet-grounded way
- discuss notable or targeted activity using stable Wireshark frame references
- pivot around protocols, packet numbers, IP pairs, and surrounding events
- export reduced slices of the PCAP for follow-on work
- discuss detection ideas interactively before generating any detection content

PIRE is not intended to replace Wireshark. It is intended to act as an investigation copilot that stays grounded in the original capture.

## 1.1 Operational model: Ingest -> Read -> Evaluate
The intended flow is:
1. **Ingest** the capture and validate/inventory it
2. **Read** enough packet-grounded context to support investigation
3. **Evaluate / Examine** according to the user's actual question

The user-facing experience should often begin with a question or investigative use case, but PIRE still needs the I/R/E pipeline underneath that experience.

## 2. Design principles

### 2.1 Interactive first
PIRE should favor interactive investigation over one-shot automated conclusions.

### 2.2 Frame fidelity
PIRE must preserve stable references back to the original packet/frame numbers so the user can follow along in Wireshark.

### 2.3 Human-reviewed detection logic
PIRE must not automatically produce detections by default. Detection output is only created after discussion and explicit user request.

### 2.4 Large-PCAP practicality
PIRE must be able to work with large captures by indexing lightly first and pulling detail on demand.

### 2.5 Honest uncertainty
If requested activity is not found, PIRE should say so clearly, provide a useful Wireshark display filter, and allow the user to return with a frame pivot.

### 2.6 Portable deployment
PIRE should be shareable so other OpenClaw users can run it with minimal friction.

### 2.7 Library-first knowledge reuse
PIRE should treat the library as a first-class investigation input. Before treating a protocol or behavior as unfamiliar, OpenClaw should check what has already been saved and use that to guide the next step.

### 2.8 Separated knowledge layers
PIRE should keep at least three knowledge layers distinct:
- protocol knowledge: more permanent understanding of how the protocol works and what normal often looks like
- experiential knowledge: prior cases, attack ideas, detections, heuristics, and investigative lessons
- current case knowledge: working notes and hypotheses for the present PCAP or PCAP set

PIRE may promote material from current case knowledge into protocol or experiential knowledge, but that promotion should be deliberate rather than automatic.

### 2.9 Durable knowledge capture
PIRE should convert useful findings into durable library artifacts, especially for protocols, normal-pattern baselines, and reusable investigative heuristics.

## 3. Primary user stories

### 3.1 Broad exploratory hunting
User examples:
- "Do you see anything interesting?"
- "Do you see anything malicious?"

Expected behavior:
- PIRE examines the PCAP in bounded stages
- gives a concise, packet-grounded summary of the current slice/findings
- stops and waits for the user to say `next` before continuing

### 3.2 Protocol-guided exploratory hunting
User examples:
- "I'm looking for interesting HTTP activity"
- "Show me suspicious DNS behavior"
- "Anything notable in SMB?"

Expected behavior:
- PIRE scopes the hunt to the named protocol first
- summarizes notable findings with frame references
- pauses after a bounded set of findings and waits for `next`

### 3.3 Event/pivot-driven investigation
User examples:
- "Look at frame 1842"
- "What happened before and after this Kerberos event?"
- "Follow traffic related to this IP pair"

Expected behavior:
- PIRE resolves the pivot
- extracts nearby context and related flows/conversations
- summarizes what happened before, at, and after the event

### 3.4 Detection ideation after review
User examples:
- "What detection ideas come from this sequence?"
- "Turn this into a Suricata concept"
- "Now write the Zeek logic"

Expected behavior:
- PIRE discusses possible detection approaches first
- waits for agreement
- only generates the requested detection artifact after explicit instruction

### 3.5 Export for reduced samples
User examples:
- "Export frames 800-920"
- "Cut traffic between these two IPs"
- "Give me just the relevant conversation"

Expected behavior:
- PIRE creates a reduced PCAP or equivalent export artifact
- preserves the relationship to the original capture where possible

### 3.6 Protocol learning and library enrichment
User examples:
- "Anything interesting in the OPC UA?"
- "Use this traffic to learn more about OPC UA"
- "Save what we learn about this protocol for later"

Expected behavior:
- PIRE identifies the protocol in the traffic
- OpenClaw checks the library for existing protocol knowledge and experiential knowledge first
- OpenClaw uses packet-grounded evidence plus external reference knowledge when needed
- when useful, OpenClaw combines existing library knowledge and observed packet details to query an API or other reference source in a targeted way
- PIRE distinguishes protocol knowledge, experiential knowledge, and current-case observations
- PIRE saves distilled knowledge back into the right library category rather than mixing it all together

### 3.7 User-directed API-question loop
User examples:
- "Show me what we know so far and what we should ask next"
- "Ask questions 1 through 3"
- "Ask 1, then 5, then 2"
- "Don’t list options — just ask this exact question"

Expected behavior:
- PIRE summarizes the current-case evidence, experiential knowledge, and protocol knowledge relevant to the question
- PIRE proposes a numbered list of candidate API/reference questions with supporting packet-grounded evidence when that helps the user steer
- the user chooses which questions to ask and in what order
- if the user already provides one precise external question, PIRE may skip the numbered list and ask that directly
- PIRE returns the answers, discusses them, and loops back into the next user-directed question

### 3.8 Persistent guided investigation state
While PIRE is active, OpenClaw should keep an ongoing background investigative posture.

Expected behavior:
- allow natural conversation and improvisation
- keep checking whether knowledge gaps remain
- keep formulating candidate questions and next steps in the background
- avoid being pulled so far off-topic that the investigative thread is lost
- gently steer back toward useful outputs when appropriate
- ask whether to stop PIRE if the conversation has clearly moved away from the active investigation

## 4. Non-goals for v1
PIRE v1 should not try to:
- replace Wireshark as a full GUI packet browser
- automatically generate broad detections from every PCAP without human review
- solve every protocol deeply and perfectly in v1
- fully correlate many giant PCAPs at once as a default mode
- rely on decrypted payloads being available

## 5. Investigation modes

### 5.1 Broad exploratory mode
Used when the user asks broad questions without a protocol or event pivot.

Behavior:
- inspect progressively
- summarize bounded findings
- stop and wait for `next`

### 5.2 Protocol-guided exploratory mode
Used when the user names a protocol or family of traffic to examine.

Behavior:
- focus on the named protocol first
- check the library for prior protocol notes and experiential notes before deeper interpretation
- collect the current-case packet evidence relevant to the user's question
- highlight interesting or suspicious activity
- cite frame numbers
- separate prior knowledge, experiential knowledge, and newly observed facts
- summarize the relevant evidence and knowledge before asking external questions
- use targeted API/reference queries when packet details plus existing knowledge suggest a precise follow-up question
- present numbered candidate questions when user choice should guide the next step
- stop and wait for `next`

### 5.3 Pivot mode
Used when the user gives a frame number, host pair, protocol stream, or similar anchor.

Behavior:
- resolve the pivot
- gather immediate context
- gather relevant surrounding activity
- summarize the local sequence
- if the user pivots to a different protocol or topic within the same PCAP/case, prefer treating it as a case refinement rather than a fresh case unless the context clearly resets

### 5.4 Verification fallback mode
Used when requested activity is not found.

Behavior:
- say the activity was not found in the current analysis
- provide a Wireshark display filter that would locate it if present
- ask the user to manually verify and return with a frame if needed

## 6. Data fidelity requirements
PIRE should preserve, expose, or derive where possible:
- original frame number
- timestamp
- source IP
- destination IP
- transport protocol
- ports where relevant
- application protocol where identifiable
- stream/conversation IDs where available
- packet ordering relative to the original PCAP

These fields are the backbone of Wireshark follow-along analysis.

## 7. Protocol posture
PIRE should be generic by default, while giving special attention to protocols the user expects to examine often.

Important protocol families discussed so far:
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
- OT/ICS protocols such as MODBUS, DNP3, BACnet, Profinet, and others

### 7.1 Encrypted traffic handling
For encrypted traffic, PIRE should clearly state payload visibility limits and rely on metadata and sequence context such as:
- timing
- endpoints
- ports
- TLS metadata where available
- neighboring protocol activity
- transaction ordering and correlation

## 8. Large-PCAP strategy
PIRE must assume some captures will be very large.

### 8.1 Lightweight ingest
The first pass should gather lightweight metadata only, such as:
- capinfos summary
- start/end times
- file size
- encapsulation and packet count
- top protocols
- endpoint summaries
- conversation summaries
- stream counts

### 8.2 On-demand deep extraction
Detailed extraction should happen only when needed, such as when the user asks for:
- a specific frame
- surrounding packets
- a specific protocol
- a host pair
- a conversation/stream
- an export slice

### 8.3 Stepped review
Broad hunts should be broken into bounded findings and user-controlled continuation via `next`.

## 9. Detection workflow policy
The workflow should be:
1. observe the traffic
2. consult the library and identify what is already known
3. separate the relevant current-case evidence, experiential knowledge, and protocol knowledge
4. discuss what the current traffic adds or changes
5. discuss potential detection logic
6. optionally offer or perform targeted API/reference questions to improve the detection design
7. get explicit user approval
8. generate only the requested detection form

Supported detection outputs may eventually include:
- Suricata rules
- Zeek scripts or logic sketches
- Splunk SPL queries

But v1 should treat these as downstream outputs, not the first move.

## 10. Export requirements
PIRE v1 should support at least:
- frame range export
- IP-pair conversation export
- all protocols between two IPs
- protocol-specific traffic between two IPs where feasible
- time-window export
- stream/conversation export where cleanly identifiable

Outputs should be suitable for reduced repro samples and further analysis.

## 11. Input model
### 11.1 Preferred initial input methods
Because generic chat attachment support may be limited, v1 should support:
- explicit file path input
- a known incoming/drop folder
- files transferred in externally, such as by SCP

### 11.2 Practical default
A practical v1 convention could be:
- incoming directory: `/home/claw/.openclaw/workspace/pire/incoming/`
- output directory: `/home/claw/.openclaw/workspace/pire/output/`
- export directory: `/home/claw/.openclaw/workspace/pire/exports/`
- cache/index directory: `/home/claw/.openclaw/workspace/pire/cache/`

### 11.3 Future enhancement
If OpenClaw later supports arbitrary file attachments well, PIRE should accept direct chat-uploaded PCAPs as another ingest source.

## 12. Proposed architecture
PIRE should be built in three layers, with explicit library-aware reasoning behavior in the OpenClaw layer.

### 12.1 Layer 1: CLI engine
A command-line tool providing stable, scriptable operations such as:
- ingest
- summary
- focus
- around
- proto
- pair
- export

Example command shapes:
- `pire ingest <pcap>`
- `pire summary <pcap>`
- `pire focus --frame <n>`
- `pire around --frame <n> --before <count> --after <count>`
- `pire proto --name <protocol>`
- `pire pair --src <ip> --dst <ip>`
- `pire export --frames <start>-<end>`
- `pire export --pair <ip1>,<ip2>`

### 12.2 Layer 2: Container runtime
A Docker/container environment should package the analysis dependencies so PIRE runs consistently on other OpenClaw systems.

Likely toolset:
- tshark
- editcap
- mergecap
- capinfos
- tcpdump
- jq
- yq
- ripgrep
- optional tcpflow/ngrep
- optional zeek
- optional suricata
- optional file/xxd/sqlite3

### 12.3 Layer 3: OpenClaw skill/integration
An OpenClaw skill should define:
- what PIRE is for
- how to ingest PCAPs
- how to preserve frame references
- how to handle broad hunts vs protocol hunts vs frame pivots
- how to pause for `next`
- how to handle not-found cases
- how to avoid premature detection generation
- how to consult the library before protocol interpretation
- how to save distilled findings back into the library after investigation
- how to maintain a persistent PIRE guidance state while the investigation is active
- how to notice drift and decide when to softly ask whether PIRE should be stopped

### 12.4 Protocol-learning prompt contract
When a protocol-focused investigation begins, the OpenClaw layer should guide the agent through a repeatable prompt contract:
1. identify what protocol is present and what evidence supports that identification
2. check the library for prior protocol notes, experiential notes, baselines, or saved heuristics about that protocol
3. state what is already known before claiming novelty
4. inspect packet-grounded details from the current PCAP
5. summarize the current-case evidence, experiential knowledge, and protocol knowledge relevant to the user's question
6. if useful, generate a numbered list of targeted API/reference questions grounded in that combined context
7. structure each proposed question with: the question, why we are asking, current-case PCAP evidence, relevant experiential knowledge, relevant protocol knowledge, and what kind of answer would help next
8. ask the selected questions in the user-chosen order, or continue without them if they are not needed
9. explain what appears normal, notable, or uncertain
10. decide whether the result belongs in protocol knowledge, experiential knowledge, current case knowledge, or more than one
11. save the distilled result in a reusable library form

The prompt contract should bias toward reuse and extension of existing knowledge, not repeated reinvention.

Suggested standing internal fields while PIRE is active:
- current PIRE goal
- current-case evidence snapshot
- relevant experiential knowledge snapshot
- relevant protocol knowledge snapshot
- unresolved gaps
- candidate next questions
- save-now items in case the session stops

### 12.5 Persistent guidance behavior
While PIRE is active, the OpenClaw layer should maintain a background guidance state.

That guidance state should:
- preserve the current investigative thread
- tolerate improvisation and broad discussion without losing direction
- keep checking the library and the current evidence for unresolved gaps
- continue preparing candidate questions and useful summaries in the background
- help the agent mention what matters and what is still missing
- support a soft-stop flow when the user appears to have moved on
- keep producing progress even during long protocol discussions by checking knowledge, identifying gaps, and preparing useful next moves

### 12.6 Soft-stop and closure flow
If the user appears to have moved away from the active PIRE investigation, OpenClaw may ask whether to stop PIRE.

If the user confirms, the system should:
1. save relevant findings into protocol knowledge, experiential knowledge, current case knowledge, or a deliberate promotion path between them
2. preserve current-case state so the investigation can be resumed later if needed
3. run normal library-maintenance work such as transcript/memory saving
4. then release the persistent PIRE guidance state and continue with the new task

## 13. Suggested implementation posture
### 13.1 Decoder strategy
Use tshark/Wireshark-aligned decoding as the primary interpretation path.

Reason:
- better alignment with what the user sees in Wireshark
- stable field extraction
- mature protocol decoder coverage

### 13.2 Python layer
Use Python as the orchestration and normalization layer.
Likely useful packages:
- typer or click
- pydantic
- orjson
- scapy for selective tasks
- pyshark only if it adds real value over direct tshark wrappers

The default bias should be toward calling mature CLI tools and normalizing their output, not reinventing packet decoding.

## 13.3 Knowledge-saving expectations
When PIRE learns something useful from a protocol-focused investigation, it should save structured, reusable notes rather than only ephemeral chat output.

The saved result should explicitly indicate whether it is:
- protocol knowledge
- experiential knowledge
- current case knowledge
- or a deliberate promotion from current case knowledge into one of the longer-lived categories

Recommended saved elements include:
- protocol name and short overview
- what the library already knew before this PCAP
- what this PCAP added, confirmed, or contradicted
- representative frame references
- observed normal-pattern candidates or baselines
- useful Wireshark and tshark filters
- unresolved questions
- pointers to source PCAPs, reduced exports, or artifacts when available
- whether an external API/reference query was used and what question it was answering

### 13.3.1 Proposed library structure
A practical initial structure is:
- `library/protocols/<protocol>/` for durable protocol knowledge
- `library/experience/<protocol-or-theme>/` for experiential knowledge
- `library/cases/<case-id>/` for current-case knowledge and active investigation state

### 13.3.2 Minimum note templates
Protocol knowledge notes should capture:
- protocol overview
- terminology and important fields
- common roles/components
- common flows
- normal-pattern expectations
- useful filters

Experiential knowledge notes should capture:
- case/theme summary
- observed or hypothesized wire behavior
- related detections, heuristics, or lessons
- confidence/maturity
- related protocols or case links

Current-case notes should capture:
- case id and objective
- PCAP inventory
- frame-anchored findings
- working hypotheses
- related protocol/experiential links
- candidate API questions
- promotion candidates

Draft markdown templates are saved at:
- `/home/claw/.openclaw/workspace/projects/PIRE/templates/protocol-core-template.md`
- `/home/claw/.openclaw/workspace/projects/PIRE/templates/experiential-note-template.md`
- `/home/claw/.openclaw/workspace/projects/PIRE/templates/current-case-template.md`

### 13.3.3 Concrete knowledge-link / promotion format
Use a JSON link file to track cross-category relationships and promotion decisions, for example:
- `library/cases/<case-id>/knowledge-links.json`

Suggested record format:
```json
[
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
  },
  {
    "link_id": "kl-0002",
    "source_case": "2026-05-02-opcua-bms-rerun-a",
    "source_note": "library/cases/2026-05-02-opcua-bms-rerun-a/current-case.md#L58",
    "target_category": "experience",
    "target_path": "library/experience/opcua/opcua-anomaly-001.md",
    "relation": "candidate-relevance",
    "reason": "Observed pattern may resemble a previously documented OPC UA anomaly idea.",
    "status": "accepted",
    "created_at": "2026-05-02T18:10:00Z",
    "updated_at": "2026-05-02T18:12:00Z"
  }
]
```

Recommended relation values:
- `consulted`
- `supports`
- `contradicts`
- `extends`
- `candidate-relevance`
- `promote-candidate`
- `promoted-to`
- `derived-from`

Recommended status values:
- `proposed`
- `accepted`
- `rejected`
- `superseded`

## 13.4 Stop/resume state expectations
PIRE should preserve resumable case state whenever an active investigation may pause or stop.

Recommended state fields include:
- active case id
- current user question
- current protocol/topic focus
- relevant pcap files
- latest evidence summary
- linked experiential knowledge
- linked protocol knowledge
- outstanding questions
- proposed API questions and which ones were already asked
- save-now items
- last recommended next step

### 13.4.1 Concrete case-state file format
Use a single JSON state file per active case, for example:
- `library/cases/<case-id>/case-state.json`

Suggested format:
```json
{
  "schema_version": "1.0",
  "case_id": "2026-05-02-opcua-bms-rerun-a",
  "status": "active",
  "created_at": "2026-05-02T16:10:00Z",
  "updated_at": "2026-05-02T18:07:00Z",
  "user_goal": "Use this traffic to understand OPC UA behavior and identify anything notable.",
  "current_question": "What OPC UA behaviors in this PCAP look normal vs worth deeper scrutiny?",
  "current_focus": {
    "type": "protocol",
    "value": "opcua"
  },
  "pcap_inventory": [
    {
      "path": "projects/PIRE/pire/incoming/PCAP-BMS-Rerun-April26/mnetsniff-eno4_1775149064.pcap",
      "role": "primary",
      "ingested": true,
      "time_range": {
        "start": "2026-04-26T00:04:24Z",
        "end": "2026-04-26T00:14:24Z"
      },
      "tags": ["opcua", "bms"]
    }
  ],
  "evidence_snapshot": {
    "summary": "Observed OPC UA traffic between engineering workstation and server with repeated session/service exchanges.",
    "frame_refs": [421, 428, 446, 512],
    "endpoints": [
      {"src": "10.10.20.15", "dst": "10.10.20.40", "protocol": "opcua"}
    ],
    "notable_points": [
      "Repeated OPC UA service exchanges over stable endpoints.",
      "Need to verify whether observed service mix matches expected baseline behavior."
    ]
  },
  "knowledge_links": {
    "protocol": [
      {
        "id": "proto-opcua-core",
        "path": "library/protocols/opcua/core.md",
        "relation": "consulted"
      }
    ],
    "experience": [
      {
        "id": "exp-opcua-anomaly-001",
        "path": "library/experience/opcua/opcua-anomaly-001.md",
        "relation": "candidate-relevance"
      }
    ],
    "current_case": [
      {
        "id": "case-summary",
        "path": "library/cases/2026-05-02-opcua-bms-rerun-a/current-case.md",
        "relation": "primary"
      }
    ]
  },
  "api_questions": [
    {
      "id": "q1",
      "status": "proposed",
      "question": "Does this observed OPC UA service pattern align with common normal client/server behavior?",
      "why_ask": "Need help classifying whether the service mix looks routine or unusual.",
      "pcap_evidence": [421, 428, 446],
      "protocol_knowledge_refs": ["proto-opcua-core"],
      "experience_refs": ["exp-opcua-anomaly-001"]
    },
    {
      "id": "q2",
      "status": "asked",
      "asked_at": "2026-05-02T17:55:00Z",
      "question": "What OPC UA methods or service types should we pay extra attention to in industrial environments?",
      "answer_ref": "library/cases/2026-05-02-opcua-bms-rerun-a/api-answer-q2.md"
    }
  ],
  "outstanding_gaps": [
    "Confirm expected baseline service mix for this environment.",
    "Determine whether any observed objects or service timing patterns are unusual."
  ],
  "promotion_candidates": [
    {
      "source_note": "library/cases/2026-05-02-opcua-bms-rerun-a/current-case.md#L42",
      "target_category": "protocol",
      "reason": "Potential durable note about commonly observed normal OPC UA service sequencing."
    }
  ],
  "save_pressure": [
    "Need to preserve the current OPC UA baseline hypothesis before switching topics."
  ],
  "last_recommended_next_step": "Show the user numbered API questions focused on normal-vs-notable OPC UA behavior."
}
```

## 14. Error handling expectations
PIRE should handle at least these conditions cleanly:
- missing file
- unreadable/corrupt PCAP
- unsupported or poorly decoded protocol details
- no matching activity found
- frame number not present
- export selection yields no packets
- container dependency missing

For not-found investigative cases, PIRE should provide:
- a plain statement that the requested activity was not found
- a suggested Wireshark display filter
- an invitation to return with a frame number if the user sees something manually

## 15. Portability requirements
To make PIRE usable by others, the repo/distribution should include:
- Dockerfile
- docker-compose.yml
- pinned dependency list
- the PIRE CLI engine
- OpenClaw integration/skill instructions
- expected directory layout
- setup and usage documentation
- sample test cases and, if possible, sample PCAPs

It should be possible for another OpenClaw user to obtain it via:
- git clone / git pull
- or SCP of the project files

But they must also have the usage instructions that teach OpenClaw how to use PIRE, not just the raw container.

## 16. Repository naming
Tool/product name: PIRE
Possible repo name: `pire-openclaw`

This is still flexible, but keeping the product name as PIRE is preferred.

## 16.5 Remaining design items
The following design items should remain explicitly on the work queue until completed:
- integration details for how the OpenClaw layer invokes PIRE commands and library writes
- exact validation/update rules for case-state and link records
- example-to-implementation mapping for how these illustrative files become generated artifacts in the live system

User-facing API question rendering conventions are drafted at:
- `/home/claw/.openclaw/workspace/projects/PIRE/docs/api-question-rendering-conventions.md`

Example repository layout and artifacts are drafted at:
- `/home/claw/.openclaw/workspace/projects/PIRE/examples/README-EXAMPLES.md`

## 17. v1 milestone plan

### Milestone 1: skeleton and environment
- create repo structure
- create Dockerfile and docker-compose
- install core packet tools
- define input/output/cache layout
- create placeholder CLI

### Milestone 2: ingest and metadata
- implement `ingest`
- implement lightweight metadata extraction
- store normalized summary artifacts

### Milestone 3: frame and protocol pivots
- implement frame lookup
- implement surrounding packet window extraction
- implement protocol-focused summaries
- implement host-pair pivots

### Milestone 4: stepped investigation behavior
- implement bounded result chunking
- implement continuation model for `next`
- implement not-found fallback with suggested Wireshark filters

### Milestone 5: export support
- implement frame-range export
- implement IP-pair export
- implement conversation/stream export where practical

### Milestone 6: OpenClaw skill/integration
- create the PIRE skill/instructions
- define prompt/behavior guidance
- document the user workflow

### Milestone 7: detection ideation support
- document the interaction pattern for Suricata, Zeek, and Splunk follow-on work
- ensure generation only happens after explicit request

## 18. Immediate next build target
The next practical build step should be to create the initial repository structure and container scaffolding so PIRE can start ingesting and summarizing a real PCAP as early as possible.
