# Experiential Knowledge: OPC UA anomaly triage starting point

- **Title:** OPC UA anomaly triage starting point
- **Theme / protocol:** opcua
- **Status:** draft
- **Confidence / maturity:** low
- **Last updated:** 2026-05-02T18:56:00Z
- **Related protocols:** ../../protocols/opcua/core.md
- **Related cases:** ../../cases/2026-05-02-opcua-bms-rerun-a/current-case.md
- **Related detections:** None yet

## Why this matters
When OPC UA appears in a PCAP, it is easy to overreact or underreact. A reusable experiential note helps focus attention on service usage, endpoint roles, and local baseline questions before jumping to conclusions.

## Summary of the idea / lesson / prior case
A useful first lesson is to treat OPC UA triage as a normal-vs-notable problem: identify the expected role of the client and server, then check whether the observed service mix and timing fit that role.

## Observed or hypothesized wire behavior
- Stable endpoint pairing may indicate routine use.
- Repeated service exchanges may be ordinary rather than suspicious.
- Service usage out of role may be a better lead than mere protocol presence.

## Investigative heuristics
- Start with the role of the talkers.
- Ask whether the service mix fits the environment.
- Compare repeated behaviors against local baseline before escalating.

## Detection implications
- Detection ideas may be stronger when tied to unusual service choice or role mismatch.
- Sequence-aware detections may be more useful than simple protocol presence alerts.

## When this may be environment-specific
Some environments may use OPC UA heavily and routinely, making raw presence a poor signal.

## When this may generalize
Role-based and service-based triage likely generalize across many OPC UA investigations.

## Supporting evidence or prior references
- **Source:** ../../cases/2026-05-02-opcua-bms-rerun-a/current-case.md
  - Detail: Example case with repeated OPC UA exchanges and an open normal-vs-notable question.

## Related API / research questions
- Which OPC UA service types deserve the most scrutiny in industrial environments?
- What common normal client/server patterns should we expect before treating the traffic as unusual?

## Open questions
- Which service patterns should eventually become formal experiential heuristics?
- What would a strong OPC UA detection concept look like for role mismatch or unusual service sequencing?

## Promotion / provenance notes
- Derived from: ../../cases/2026-05-02-opcua-bms-rerun-a/current-case.md
- Confidence rationale: Early reusable lesson from a design/example case, not yet battle-tested.
- Last substantive change reason: Initial example experiential note created from PIRE design work.
