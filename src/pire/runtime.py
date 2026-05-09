from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from pire.core import BASE_DIR

LIBRARY_DIR = BASE_DIR / "library"
PROTOCOLS_DIR = LIBRARY_DIR / "protocols"
EXPERIENCE_DIR = LIBRARY_DIR / "experience"
CASES_DIR = LIBRARY_DIR / "cases"
LIBRARY_TEMPLATES_DIR = LIBRARY_DIR / "templates"
CASE_INDEX_PATH = CASES_DIR / "case-index.json"
SOURCE_TEMPLATES_DIR = BASE_DIR / "templates"


class RuntimePaths(BaseModel):
    library_dir: str
    protocols_dir: str
    experience_dir: str
    cases_dir: str
    templates_dir: str
    case_index_path: str


class CaseIndexEntry(BaseModel):
    case_id: str
    status: str = "active"
    focus: str | None = None
    summary: str | None = None
    case_dir: str


class CaseIndex(BaseModel):
    schema_version: str = "1.0"
    cases: list[CaseIndexEntry] = Field(default_factory=list)


README_LIBRARY = """# PIRE Runtime Library

This is the runtime-facing knowledge and case workspace for PIRE.

The design intent is to keep three knowledge layers separate:
- `protocols/` for durable protocol knowledge
- `experience/` for reusable investigative knowledge
- `cases/` for active and resumable case material
- `templates/` for runtime-usable note templates copied from the project templates

These directories are meant to be written by PIRE runtime code and reviewed by humans.
"""

README_PROTOCOLS = """# Protocol Knowledge

Put durable protocol notes here.

Suggested shape:
- one directory per protocol
- a `core.md` note for stable baseline knowledge
- optional supporting notes as the protocol area grows
"""

README_EXPERIENCE = """# Experiential Knowledge

Put reusable prior-case lessons, heuristics, detections, and investigative notes here.

Suggested shape:
- one directory per protocol or theme
- one markdown note per reusable lesson or prior case pattern
"""

README_CASES = """# Current Cases

Each case should get its own directory.

Suggested contents:
- `current-case.md`
- `case-state.json`
- `knowledge-links.json`
- optional saved API answers or export notes
"""

README_TEMPLATES = """# Runtime Templates

These templates are copied from the top-level `templates/` directory so runtime code has a predictable place to find the current note skeletons.

Source of truth today:
- `templates/protocol-core-template.md`
- `templates/experiential-note-template.md`
- `templates/current-case-template.md`
"""

DEFAULT_CASE_STATE = {
    "schema_version": "1.0",
    "case_id": "",
    "status": "active",
    "created_at": None,
    "updated_at": None,
    "user_goal": None,
    "current_question": None,
    "current_focus": None,
    "pcap_inventory": [],
    "evidence_snapshot": {
        "summary": None,
        "frame_refs": [],
        "endpoints": [],
        "observations": [],
    },
    "knowledge_links": {"protocol": [], "experience": [], "current_case": []},
    "api_questions": [],
    "knowledge_actions": [],
    "hypotheses": [],
    "outstanding_gaps": [],
    "promotion_candidates": [],
    "save_pressure": [],
    "dismissed_knowledge_items": [],
    "last_recommended_next_step": None,
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_if_missing(path: Path, content: str) -> None:
    if not path.exists():
        path.write_text(content)


def _copy_template_if_present(src_name: str, dest_name: str | None = None) -> None:
    src = SOURCE_TEMPLATES_DIR / src_name
    if not src.exists():
        return
    dest = LIBRARY_TEMPLATES_DIR / (dest_name or src_name)
    if not dest.exists():
        dest.write_text(src.read_text())


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2))


def ensure_runtime_structure() -> RuntimePaths:
    for path in (LIBRARY_DIR, PROTOCOLS_DIR, EXPERIENCE_DIR, CASES_DIR, LIBRARY_TEMPLATES_DIR):
        path.mkdir(parents=True, exist_ok=True)

    _write_if_missing(LIBRARY_DIR / "README.md", README_LIBRARY)
    _write_if_missing(PROTOCOLS_DIR / "README.md", README_PROTOCOLS)
    _write_if_missing(EXPERIENCE_DIR / "README.md", README_EXPERIENCE)
    _write_if_missing(CASES_DIR / "README.md", README_CASES)
    _write_if_missing(LIBRARY_TEMPLATES_DIR / "README.md", README_TEMPLATES)

    _copy_template_if_present("protocol-core-template.md")
    _copy_template_if_present("experiential-note-template.md")
    _copy_template_if_present("current-case-template.md")

    if not CASE_INDEX_PATH.exists():
        CASE_INDEX_PATH.write_text(CaseIndex().model_dump_json(indent=2))

    return RuntimePaths(
        library_dir=str(LIBRARY_DIR),
        protocols_dir=str(PROTOCOLS_DIR),
        experience_dir=str(EXPERIENCE_DIR),
        cases_dir=str(CASES_DIR),
        templates_dir=str(LIBRARY_TEMPLATES_DIR),
        case_index_path=str(CASE_INDEX_PATH),
    )


def slugify_case_id(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    if not value:
        raise ValueError("Case id cannot be empty")
    return value


def case_dir(case_id: str) -> Path:
    return CASES_DIR / slugify_case_id(case_id)


def case_paths(case_id: str) -> dict[str, Path]:
    cdir = case_dir(case_id)
    return {
        "case_dir": cdir,
        "current_case": cdir / "current-case.md",
        "case_state": cdir / "case-state.json",
        "knowledge_links": cdir / "knowledge-links.json",
        "api_answers_dir": cdir / "api-answers",
    }


def load_case_index() -> CaseIndex:
    ensure_runtime_structure()
    try:
        raw = json.loads(CASE_INDEX_PATH.read_text())
        return CaseIndex.model_validate(raw)
    except Exception:
        index = CaseIndex()
        CASE_INDEX_PATH.write_text(index.model_dump_json(indent=2))
        return index


def save_case_index(index: CaseIndex) -> None:
    ensure_runtime_structure()
    CASE_INDEX_PATH.write_text(index.model_dump_json(indent=2))


def _ensure_index_entry(case_id: str, *, summary: str | None = None, focus: str | None = None, status: str = "active") -> None:
    index = load_case_index()
    slug = slugify_case_id(case_id)
    existing = next((entry for entry in index.cases if entry.case_id == slug), None)
    if existing:
        existing.status = status or existing.status
        if focus:
            existing.focus = focus
        if summary:
            existing.summary = summary
    else:
        index.cases.append(
            CaseIndexEntry(
                case_id=slug,
                case_dir=str(case_dir(slug).relative_to(BASE_DIR)),
                focus=focus,
                summary=summary,
                status=status,
            )
        )
    save_case_index(index)


def _blank_case_state(case_id: str, *, focus: str | None = None) -> dict[str, Any]:
    state = json.loads(json.dumps(DEFAULT_CASE_STATE))
    state["case_id"] = slugify_case_id(case_id)
    state["created_at"] = utc_now_iso()
    state["updated_at"] = state["created_at"]
    state["current_focus"] = {"type": "topic", "value": focus} if focus else None
    state["last_recommended_next_step"] = "Populate the case with the first real packet-grounded findings."
    return state


def _render_bullets(items: list[Any], formatter) -> str:
    if not items:
        return "- None yet\n"
    return "".join(formatter(item) for item in items)


def render_current_case_markdown(state: dict[str, Any]) -> str:
    case_id = state.get("case_id", "unknown-case")
    focus_value = (state.get("current_focus") or {}).get("value")
    evidence = state.get("evidence_snapshot") or {}
    observations = evidence.get("observations") or []
    knowledge_links = state.get("knowledge_links") or {}
    api_questions = state.get("api_questions") or []

    lines = [f"# Current Case: {case_id}", ""]
    lines.append(f"- **Case ID:** {case_id}")
    lines.append(f"- **Status:** {state.get('status', 'active')}")
    if state.get("created_at"):
        lines.append(f"- **Created:** {state['created_at']}")
    if state.get("updated_at"):
        lines.append(f"- **Last updated:** {state['updated_at']}")
    if state.get("user_goal"):
        lines.append(f"- **User goal:** {state['user_goal']}")
    if state.get("current_question"):
        lines.append(f"- **Current question:** {state['current_question']}")
    if focus_value:
        lines.append(f"- **Current focus:** {focus_value}")

    lines.extend(["", "## PCAP inventory"])
    inventory = state.get("pcap_inventory") or []
    if inventory:
        for item in inventory:
            path = item.get("path", "unknown")
            role = item.get("role") or "primary"
            tags = item.get("tags") or []
            tag_text = f" — tags: {', '.join(tags)}" if tags else ""
            lines.append(f"- `{path}` — {role}{tag_text}")
    else:
        lines.append("- None yet")

    lines.extend(["", "## Working summary"])
    lines.append(evidence.get("summary") or "No summary yet.")

    lines.extend(["", "## Frame-anchored evidence"])
    if observations:
        for obs in observations:
            frames = obs.get("frames") or []
            frame_text = ", ".join(str(frame) for frame in frames) if frames else "None specified"
            lines.append(f"- **Frame(s):** {frame_text}")
            if obs.get("observation"):
                lines.append(f"  - Observation: {obs['observation']}")
            if obs.get("interpretation"):
                lines.append(f"  - Interpretation: {obs['interpretation']}")
            if obs.get("endpoints"):
                lines.append(f"  - Endpoints: {', '.join(obs['endpoints'])}")
    else:
        lines.append("- None yet")

    lines.extend(["", "## Endpoints / conversations of interest"])
    endpoints = evidence.get("endpoints") or []
    if endpoints:
        for endpoint in endpoints:
            lines.append(f"- {endpoint}")
    else:
        lines.append("- None yet")

    lines.extend(["", "## Relevant protocol knowledge links"])
    lines.append(
        _render_bullets(knowledge_links.get("protocol") or [], lambda item: f"- {item.get('path', item)}\n").rstrip()
    )

    lines.extend(["", "## Relevant experiential knowledge links"])
    lines.append(
        _render_bullets(knowledge_links.get("experience") or [], lambda item: f"- {item.get('path', item)}\n").rstrip()
    )

    lines.extend(["", "## Candidate API questions"])
    if api_questions:
        for idx, question in enumerate(api_questions, start=1):
            lines.append(f"{idx}. **Question:** {question.get('question', 'Untitled question')}" )
            for label, key in [
                ("Why ask", "why_ask"),
                ("PCAP evidence", "pcap_evidence"),
                ("Experiential knowledge", "experiential_knowledge"),
                ("Protocol knowledge", "protocol_knowledge"),
                ("Helpful answer would", "helpful_answer_would"),
            ]:
                value = question.get(key)
                if value:
                    lines.append(f"   - **{label}:** {value}")
    else:
        lines.append("- None yet")

    lines.extend(["", "## Outstanding gaps"])
    lines.append(_render_bullets(state.get("outstanding_gaps") or [], lambda item: f"- {item}\n").rstrip())

    lines.extend(["", "## Next recommended steps"])
    next_step = state.get("last_recommended_next_step")
    lines.append(f"- {next_step}" if next_step else "- None yet")

    lines.extend(["", "## Save-now items"])
    lines.append(_render_bullets(state.get("save_pressure") or [], lambda item: f"- {item}\n").rstrip())

    return "\n".join(lines).rstrip() + "\n"


def bootstrap_case(case_id: str, *, summary: str | None = None, focus: str | None = None) -> dict[str, Any]:
    ensure_runtime_structure()
    slug = slugify_case_id(case_id)
    paths = case_paths(slug)
    paths["case_dir"].mkdir(parents=True, exist_ok=True)
    paths["api_answers_dir"].mkdir(exist_ok=True)

    if not paths["case_state"].exists():
        state = _blank_case_state(slug, focus=focus)
        if summary:
            state["evidence_snapshot"]["summary"] = summary
        _write_json(paths["case_state"], state)
    else:
        state = _load_json(paths["case_state"], _blank_case_state(slug, focus=focus))

    if not paths["knowledge_links"].exists():
        _write_json(paths["knowledge_links"], [])

    state["updated_at"] = utc_now_iso()
    _write_json(paths["case_state"], state)

    if not paths["current_case"].exists():
        paths["current_case"].write_text(render_current_case_markdown(state))

    _ensure_index_entry(slug, summary=summary, focus=focus, status=state.get("status", "active"))

    return {
        "case_id": slug,
        "case_dir": str(paths["case_dir"]),
        "current_case": str(paths["current_case"]),
        "case_state": str(paths["case_state"]),
        "knowledge_links": str(paths["knowledge_links"]),
        "api_answers_dir": str(paths["api_answers_dir"]),
    }


def load_case_state(case_id: str) -> dict[str, Any]:
    bootstrap_case(case_id)
    paths = case_paths(case_id)
    state = _load_json(paths["case_state"], _blank_case_state(case_id))
    state.setdefault("schema_version", "1.0")
    state.setdefault("status", "active")
    state.setdefault("pcap_inventory", [])
    state.setdefault("knowledge_links", {"protocol": [], "experience": [], "current_case": []})
    state.setdefault("api_questions", [])
    state.setdefault("hypotheses", [])
    state.setdefault("outstanding_gaps", [])
    state.setdefault("promotion_candidates", [])
    state.setdefault("save_pressure", [])
    state.setdefault("dismissed_knowledge_items", [])
    evidence = state.setdefault("evidence_snapshot", {})
    evidence.setdefault("summary", None)
    evidence.setdefault("frame_refs", [])
    evidence.setdefault("endpoints", [])
    evidence.setdefault("observations", [])
    return state


def save_case_state(case_id: str, state: dict[str, Any]) -> dict[str, Any]:
    slug = slugify_case_id(case_id)
    paths = case_paths(slug)
    paths["case_dir"].mkdir(parents=True, exist_ok=True)
    paths["api_answers_dir"].mkdir(exist_ok=True)
    state["case_id"] = slug
    if not state.get("created_at"):
        state["created_at"] = utc_now_iso()
    state["updated_at"] = utc_now_iso()
    _write_json(paths["case_state"], state)
    _write_json(paths["knowledge_links"], flatten_knowledge_links(state.get("knowledge_links") or {}))
    paths["current_case"].write_text(render_current_case_markdown(state))
    _ensure_index_entry(
        slug,
        summary=(state.get("evidence_snapshot") or {}).get("summary"),
        focus=(state.get("current_focus") or {}).get("value"),
        status=state.get("status", "active"),
    )
    return state


def flatten_knowledge_links(links: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for category, items in links.items():
        for item in items or []:
            entry = dict(item)
            entry.setdefault("target_category", category)
            flat.append(entry)
    return flat


def _append_unique_string(target: list[str], value: str | None) -> None:
    if value and value not in target:
        target.append(value)


def _add_observation(
    state: dict[str, Any],
    *,
    frames: list[int] | None = None,
    observation: str | None = None,
    interpretation: str | None = None,
    endpoints: list[str] | None = None,
) -> None:
    if not observation and not interpretation and not frames and not endpoints:
        return
    evidence = state.setdefault("evidence_snapshot", {"summary": None, "frame_refs": [], "endpoints": [], "observations": []})
    evidence.setdefault("frame_refs", [])
    evidence.setdefault("endpoints", [])
    evidence.setdefault("observations", [])

    for frame in frames or []:
        if frame not in evidence["frame_refs"]:
            evidence["frame_refs"].append(frame)
    for endpoint in endpoints or []:
        _append_unique_string(evidence["endpoints"], endpoint)

    candidate = {
        "frames": sorted(set(frames or [])),
        "observation": observation,
        "interpretation": interpretation,
        "endpoints": endpoints or [],
    }
    if candidate not in evidence["observations"]:
        evidence["observations"].append(candidate)


def add_pcap_to_case(case_id: str, pcap_path: str, *, role: str = "primary", tags: list[str] | None = None) -> dict[str, Any]:
    state = load_case_state(case_id)
    inventory = state.setdefault("pcap_inventory", [])
    existing = next((item for item in inventory if item.get("path") == pcap_path), None)
    if existing:
        existing["role"] = role or existing.get("role") or "primary"
        if tags:
            existing["tags"] = sorted(set((existing.get("tags") or []) + tags))
    else:
        inventory.append({"path": pcap_path, "role": role, "ingested": True, "tags": tags or []})
    return save_case_state(case_id, state)


def record_investigation_turn(
    case_id: str,
    *,
    pcap_path: str | None = None,
    user_message: str | None = None,
    focus: str | None = None,
    summary: str | None = None,
    observation: str | None = None,
    interpretation: str | None = None,
    frames: list[int] | None = None,
    endpoints: list[str] | None = None,
    next_step: str | None = None,
    gaps: list[str] | None = None,
    hypotheses: list[str] | None = None,
) -> dict[str, Any]:
    state = load_case_state(case_id)
    if pcap_path:
        add_pcap_to_case(case_id, pcap_path, tags=[focus] if focus else None)
        state = load_case_state(case_id)
    if user_message:
        state["current_question"] = user_message
    if focus:
        state["current_focus"] = {"type": "topic", "value": focus}
    if summary:
        state.setdefault("evidence_snapshot", {}).setdefault("summary", None)
        state["evidence_snapshot"]["summary"] = summary
    _add_observation(state, frames=frames, observation=observation, interpretation=interpretation, endpoints=endpoints)
    for gap in gaps or []:
        _append_unique_string(state.setdefault("outstanding_gaps", []), gap)
    for hypothesis in hypotheses or []:
        _append_unique_string(state.setdefault("hypotheses", []), hypothesis)
    if next_step:
        state["last_recommended_next_step"] = next_step
    return save_case_state(case_id, state)


def update_case_links(case_id: str, links_by_category: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    state = load_case_state(case_id)
    bucket = state.setdefault("knowledge_links", {"protocol": [], "experience": [], "current_case": []})
    for category, items in links_by_category.items():
        bucket.setdefault(category, [])
        for item in items:
            normalized = {
                "path": item.get("path"),
                "title": item.get("title"),
                "snippet": item.get("snippet"),
                "relation": item.get("relation") or "retrieved",
            }
            if normalized not in bucket[category]:
                bucket[category].append(normalized)
    return save_case_state(case_id, state)


def _find_snippet(text: str, term: str | None) -> str:
    lines = text.splitlines()
    if not term:
        for line in lines:
            cleaned = line.strip()
            if cleaned:
                return cleaned[:240]
        return ""
    lowered = term.lower()
    for line in lines:
        if lowered in line.lower():
            return line.strip()[:240]
    return ""


def _note_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        if line.startswith("#"):
            return line.lstrip("# ").strip()
    return fallback


def _scan_notes(root: Path, *, term: str | None = None, limit: int = 5, exclude_names: set[str] | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    exclude_names = exclude_names or set()
    if not root.exists():
        return results
    for path in sorted(root.rglob("*.md")):
        if path.name in exclude_names:
            continue
        try:
            text = path.read_text()
        except Exception:
            continue
        if term and term.lower() not in text.lower() and term.lower() not in str(path).lower():
            continue
        results.append(
            {
                "path": str(path.relative_to(LIBRARY_DIR)),
                "title": _note_title(text, path.stem),
                "snippet": _find_snippet(text, term),
            }
        )
        if len(results) >= limit:
            break
    return results


def retrieve_protocol_knowledge(topic: str, limit: int = 5) -> list[dict[str, Any]]:
    return _scan_notes(PROTOCOLS_DIR, term=topic, limit=limit, exclude_names={"README.md"})


def retrieve_experiential_knowledge(topic: str, limit: int = 5) -> list[dict[str, Any]]:
    return _scan_notes(EXPERIENCE_DIR, term=topic, limit=limit, exclude_names={"README.md"})


def retrieve_current_case_knowledge(case_id: str, topic: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
    cdir = case_dir(case_id)
    results = _scan_notes(cdir, term=topic, limit=limit, exclude_names={"README.md"})
    if results:
        return results
    return _scan_notes(cdir, term=None, limit=1, exclude_names={"README.md"})


def retrieve_layered_knowledge(case_id: str, topic: str, limit_per_layer: int = 5) -> dict[str, list[dict[str, Any]]]:
    return {
        "protocol": retrieve_protocol_knowledge(topic, limit=limit_per_layer),
        "experience": retrieve_experiential_knowledge(topic, limit=limit_per_layer),
        "current_case": retrieve_current_case_knowledge(case_id, topic=topic, limit=limit_per_layer),
    }


def ensure_case_for_pcap(pcap_path: str, *, focus: str | None = None) -> dict[str, Any]:
    stem = Path(pcap_path).stem
    case_id = slugify_case_id(stem)
    bootstrap_case(case_id, summary=f"Auto-created case for {pcap_path}", focus=focus)
    add_pcap_to_case(case_id, pcap_path, tags=[focus] if focus else None)
    return {"case_id": case_id, **{key: str(value) for key, value in case_paths(case_id).items()}}


def _next_question_id(existing: list[dict[str, Any]]) -> str:
    max_num = 0
    for item in existing:
        qid = str(item.get("id") or "")
        if qid.startswith("q") and qid[1:].isdigit():
            max_num = max(max_num, int(qid[1:]))
    return f"q{max_num + 1}"


def add_api_questions(case_id: str, questions: list[dict[str, Any]]) -> dict[str, Any]:
    state = load_case_state(case_id)
    bucket = state.setdefault("api_questions", [])
    created: list[dict[str, Any]] = []
    for question in questions:
        normalized = {
            "id": question.get("id") or _next_question_id(bucket),
            "status": question.get("status") or "proposed",
            "question": question.get("question") or "Untitled question",
            "why_ask": question.get("why_ask"),
            "pcap_evidence": question.get("pcap_evidence"),
            "experiential_knowledge": question.get("experiential_knowledge"),
            "protocol_knowledge": question.get("protocol_knowledge"),
            "helpful_answer_would": question.get("helpful_answer_would"),
            "created_at": question.get("created_at") or utc_now_iso(),
            "updated_at": utc_now_iso(),
            "asked_at": question.get("asked_at"),
            "answered_at": question.get("answered_at"),
            "answer_path": question.get("answer_path"),
        }
        bucket.append(normalized)
        created.append(normalized)
    save_case_state(case_id, state)
    return {"case_id": slugify_case_id(case_id), "created": created, "api_questions": state.get("api_questions", [])}


def add_knowledge_action(case_id: str, action: dict[str, Any]) -> dict[str, Any]:
    state = load_case_state(case_id)
    bucket = state.setdefault("knowledge_actions", [])
    normalized = {
        "id": action.get("id") or f"ka{len(bucket) + 1}",
        "kind": action.get("kind") or "browser",
        "ip": action.get("ip"),
        "section_id": action.get("section_id"),
        "line_index": action.get("line_index"),
        "title": action.get("title") or "Untitled knowledge action",
        "summary": action.get("summary"),
        "payload": action.get("payload") or {},
        "created_at": action.get("created_at") or utc_now_iso(),
        "updated_at": utc_now_iso(),
    }
    bucket.append(normalized)
    save_case_state(case_id, state)
    return normalized


def update_api_question(case_id: str, question_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    state = load_case_state(case_id)
    bucket = state.setdefault("api_questions", [])
    target = next((item for item in bucket if item.get("id") == question_id), None)
    if not target:
        raise ValueError(f"Unknown question id: {question_id}")
    for key, value in patch.items():
        if value is not None:
            target[key] = value
    target["updated_at"] = utc_now_iso()
    save_case_state(case_id, state)
    return target


def save_api_answer(case_id: str, question_id: str, *, answer_summary: str, answer_body: str | None = None) -> dict[str, Any]:
    state = load_case_state(case_id)
    bucket = state.setdefault("api_questions", [])
    target = next((item for item in bucket if item.get("id") == question_id), None)
    if not target:
        raise ValueError(f"Unknown question id: {question_id}")
    paths = case_paths(case_id)
    paths["api_answers_dir"].mkdir(parents=True, exist_ok=True)
    answer_path = paths["api_answers_dir"] / f"{question_id}.md"
    content_lines = [
        f"# API Answer: {question_id}",
        "",
        f"- **Question ID:** {question_id}",
        f"- **Asked at:** {target.get('asked_at') or utc_now_iso()}",
        f"- **Answered at:** {utc_now_iso()}",
        f"- **Status:** answered",
        "",
        "## Question",
        target.get("question") or "Untitled question",
        "",
        "## Short answer",
        answer_summary,
    ]
    if answer_body:
        content_lines.extend(["", "## Detail", answer_body])
    answer_path.write_text("\n".join(content_lines).rstrip() + "\n")
    target["status"] = "answered"
    target["asked_at"] = target.get("asked_at") or utc_now_iso()
    target["answered_at"] = utc_now_iso()
    target["answer_path"] = str(answer_path.relative_to(LIBRARY_DIR))
    target["updated_at"] = utc_now_iso()
    state["last_recommended_next_step"] = "Review the saved API answer and decide whether to ask another question or return to packet pivots."
    save_case_state(case_id, state)
    return {"question": target, "answer_path": str(answer_path)}


def select_api_question(case_id: str, question_id: str) -> dict[str, Any]:
    return update_api_question(case_id, question_id, {"status": "selected", "asked_at": utc_now_iso()})


def case_snapshot(case_id: str) -> dict[str, Any]:
    state = load_case_state(case_id)
    return {
        "case_id": state.get("case_id"),
        "status": state.get("status"),
        "current_focus": state.get("current_focus"),
        "current_question": state.get("current_question"),
        "active_question_ids": state.get("active_question_ids") or [],
        "pcap_inventory": state.get("pcap_inventory") or [],
        "evidence_snapshot": state.get("evidence_snapshot") or {},
        "knowledge_links": state.get("knowledge_links") or {},
        "api_questions": state.get("api_questions") or [],
        "knowledge_actions": state.get("knowledge_actions") or [],
        "outstanding_gaps": state.get("outstanding_gaps") or [],
        "promotion_candidates": state.get("promotion_candidates") or [],
        "save_pressure": state.get("save_pressure") or [],
        "hypotheses": state.get("hypotheses") or [],
        "last_recommended_next_step": state.get("last_recommended_next_step"),
    }
