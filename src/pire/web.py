from __future__ import annotations

import json
import logging
import re
import shlex
import shutil
import time
from pathlib import Path
from typing import Any

from pire.openclaw import ask_openclaw, openclaw_status

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from pire.core import (
    CACHE_DIR,
    DATA_DIR,
    EXPORTS_DIR,
    INCOMING_DIR,
    OUTPUT_DIR,
    STATE_PATH,
    ZEEK_LOG_DIR,
    around_rows,
    build_overview,
    conversation_page,
    current_pcap,
    endpoint_page,
    endpoint_rows,
    ensure_dirs,
    export_frame_range,
    host_page,
    ingest_pcap,
    list_pcaps,
    metadata_for_pcap,
    pair_rows,
    protocol_hierarchy,
    resolve_pcap,
    run_command,
    safe_zeek_summary,
    set_current_pcap,
    summary_rows,
    zeek_endpoint_activity,
    zeek_ip_profile,
    zeek_log_fields,
    zeek_log_rows,
    zeek_log_fallback_rows,
    _merge_zeek_and_fallback_rows,
    zeek_run_dir,
)
from pire.runtime import (
    LIBRARY_DIR,
    add_api_questions,
    add_knowledge_action,
    case_dir,
    case_snapshot,
    ensure_case_for_pcap,
    load_case_index,
    load_case_state,
    record_investigation_turn,
    retrieve_layered_knowledge,
    save_api_answer,
    save_case_index,
    save_case_state,
    select_api_question,
    slugify_case_id,
    update_case_links,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
ALLOWED_TERMINAL_BINARIES = {"pire", "capinfos", "tshark", "editcap", "mergecap", "tcpdump", "zeek", "zeek-cut", "zkg", "jq", "rg", "yq"}
logger = logging.getLogger("uvicorn.error")

app = FastAPI(title="PIRE UI", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class LoadRequest(BaseModel):
    pcap: str


class ChatAttachment(BaseModel):
    kind: str = "image"
    name: str
    mime_type: str
    data_url: str


class ChatRequest(BaseModel):
    message: str
    pcap: str | None = None
    selected_knowledge: dict[str, Any] | None = None
    attachments: list[ChatAttachment] = []


class TerminalRequest(BaseModel):
    command: str
    pcap: str | None = None


class RetrievalRequest(BaseModel):
    topic: str
    case_id: str | None = None
    pcap: str | None = None


class QuestionCreateRequest(BaseModel):
    case_id: str | None = None
    pcap: str | None = None
    questions: list[dict[str, Any]]


class QuestionSelectRequest(BaseModel):
    case_id: str | None = None
    pcap: str | None = None
    question_id: str


class QuestionAnswerRequest(BaseModel):
    case_id: str | None = None
    pcap: str | None = None
    question_id: str
    answer_summary: str
    answer_body: str | None = None


class DossierQuestionSelectRequest(BaseModel):
    ip: str
    section_id: str
    case_id: str | None = None
    pcap: str | None = None


class DossierKnowledgeActionRequest(BaseModel):
    ip: str
    section_id: str
    kind: str
    line_index: int | None = None
    case_id: str | None = None
    pcap: str | None = None


class DeletePcapRequest(BaseModel):
    pcap: str
    delete_exports: bool = True


class DeleteCaseRequest(BaseModel):
    case_id: str | None = None
    pcap: str | None = None
    unload_if_active: bool = True


class KnowledgeActionRequest(BaseModel):
    case_id: str | None = None
    pcap: str | None = None
    item_id: str
    source_kind: str
    title: str
    summary: str | None = None
    rationale: str | None = None
    tags: list[str] = []
    comment: str | None = None
    status: str = "promoted"


class KnowledgeNoteUpdateRequest(BaseModel):
    path: str
    content: str


def _dir_size_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for path in root.rglob("*"):
        if path.is_file():
            try:
                total += path.stat().st_size
            except FileNotFoundError:
                continue
    return total


def _file_count(root: Path, pattern: str = "*") -> int:
    if not root.exists():
        return 0
    return sum(1 for path in root.rglob(pattern) if path.is_file() and not path.name.startswith("."))


def _runtime_storage_summary() -> dict[str, Any]:
    return {
        "incoming": {
            "bytes": _dir_size_bytes(INCOMING_DIR),
            "pcap_count": len(list_pcaps()),
        },
        "exports": {
            "bytes": _dir_size_bytes(EXPORTS_DIR),
            "file_count": _file_count(EXPORTS_DIR),
        },
        "zeek_cache": {
            "bytes": _dir_size_bytes(ZEEK_LOG_DIR),
            "run_count": sum(1 for path in ZEEK_LOG_DIR.iterdir() if path.is_dir()) if ZEEK_LOG_DIR.exists() else 0,
        },
        "library": {
            "bytes": _dir_size_bytes(BASE_DIR.parents[1] / "library"),
            "file_count": _file_count(BASE_DIR.parents[1] / "library"),
        },
        "output": {
            "bytes": _dir_size_bytes(OUTPUT_DIR),
            "file_count": _file_count(OUTPUT_DIR),
        },
        "total_runtime_bytes": _dir_size_bytes(DATA_DIR) + _dir_size_bytes(BASE_DIR.parents[1] / "library"),
    }


def _prune_empty_parents(path: Path, stop_at: Path) -> None:
    current = path.parent
    while current != stop_at and stop_at in current.parents:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def _delete_path(path: Path, deleted: list[dict[str, Any]]) -> None:
    if not path.exists():
        return
    if path.is_dir():
        size = _dir_size_bytes(path)
        shutil.rmtree(path)
        deleted.append({"path": str(path), "kind": "dir", "bytes": size})
        return
    size = path.stat().st_size
    path.unlink()
    deleted.append({"path": str(path), "kind": "file", "bytes": size})


def _delete_pcap_runtime_data(pcap: str, *, delete_exports: bool = True) -> dict[str, Any]:
    ensure_dirs()
    pcap_path = resolve_pcap(pcap)
    deleted: list[dict[str, Any]] = []
    zeek_dir = zeek_run_dir(pcap)
    _delete_path(zeek_dir, deleted)
    _delete_path(OUTPUT_DIR / f"{pcap_path.name}.capinfos.txt", deleted)
    _delete_path(OUTPUT_DIR / f"{pcap_path.name}.metadata.json", deleted)
    if delete_exports and EXPORTS_DIR.exists():
        for export_path in EXPORTS_DIR.iterdir():
            if not export_path.is_file() or export_path.name.startswith("."):
                continue
            if export_path.name.startswith(f"{pcap_path.stem}-") or export_path.name.startswith(f"{pcap_path.name}-"):
                _delete_path(export_path, deleted)
    _delete_path(pcap_path, deleted)
    _prune_empty_parents(pcap_path, INCOMING_DIR)
    return {
        "deleted": deleted,
        "bytes_freed": sum(item.get("bytes", 0) for item in deleted),
        "storage": _runtime_storage_summary(),
    }


def _prune_orphan_zeek_cache() -> dict[str, Any]:
    ensure_dirs()
    deleted: list[dict[str, Any]] = []
    if not ZEEK_LOG_DIR.exists():
        return {"deleted": deleted, "bytes_freed": 0, "storage": _runtime_storage_summary()}
    for run_dir in ZEEK_LOG_DIR.iterdir():
        if not run_dir.is_dir():
            continue
        meta_path = run_dir / "_meta.json"
        if not meta_path.exists():
            _delete_path(run_dir, deleted)
            continue
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            _delete_path(run_dir, deleted)
            continue
        relative_path = meta.get("relative_path")
        if not relative_path:
            _delete_path(run_dir, deleted)
            continue
        try:
            resolve_pcap(relative_path)
        except FileNotFoundError:
            _delete_path(run_dir, deleted)
    return {
        "deleted": deleted,
        "bytes_freed": sum(item.get("bytes", 0) for item in deleted),
        "storage": _runtime_storage_summary(),
    }


def _delete_all_exports() -> dict[str, Any]:
    ensure_dirs()
    deleted: list[dict[str, Any]] = []
    if EXPORTS_DIR.exists():
        for export_path in EXPORTS_DIR.iterdir():
            if export_path.is_file() and not export_path.name.startswith("."):
                _delete_path(export_path, deleted)
    return {
        "deleted": deleted,
        "bytes_freed": sum(item.get("bytes", 0) for item in deleted),
        "storage": _runtime_storage_summary(),
    }


KNOWLEDGE_OBJECTS_DIR = LIBRARY_DIR / "knowledge-objects"
KNOWLEDGE_TAGS = [
    "Protocol",
    "Experience",
    "Detection",
    "Detection Syntax",
    "SIEM Syntax",
    "Field Mapping",
    "Heuristic",
    "Baseline / Normal",
    "False Positive Lesson",
    "Case Pattern",
    "Reusable Query",
    "Platform Quirk",
    "API Answer",
    "Case-Specific",
    "Reusable",
    "Needs Review",
    "Stale",
]


def _knowledge_object_dir(case_id: str) -> Path:
    return KNOWLEDGE_OBJECTS_DIR / case_id


def _knowledge_object_path(case_id: str, item_id: str) -> Path:
    safe_item = re.sub(r"[^a-zA-Z0-9._-]+", "-", item_id).strip("-") or "item"
    return _knowledge_object_dir(case_id) / f"{safe_item}.json"


def _load_knowledge_object(case_id: str, item_id: str) -> dict[str, Any] | None:
    path = _knowledge_object_path(case_id, item_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _set_knowledge_dismissed(case_id: str, item_id: str, dismissed: bool) -> dict[str, Any]:
    state = load_case_state(case_id)
    bucket = state.setdefault("dismissed_knowledge_items", [])
    if dismissed:
        if item_id not in bucket:
            bucket.append(item_id)
    else:
        state["dismissed_knowledge_items"] = [value for value in bucket if value != item_id]
    return save_case_state(case_id, state)


def _delete_knowledge_object(case_id: str, item_id: str) -> None:
    existing = _load_knowledge_object(case_id, item_id) or {}
    object_path = _knowledge_object_path(case_id, item_id)
    if object_path.exists():
        object_path.unlink()
        _prune_empty_parents(object_path, KNOWLEDGE_OBJECTS_DIR)
    for relative in existing.get("projection_paths") or []:
        try:
            path = _resolve_library_note(relative)
        except HTTPException:
            continue
        if path.exists():
            path.unlink()
            _prune_empty_parents(path, LIBRARY_DIR)


def _save_knowledge_object(case_id: str, item_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    object_dir = _knowledge_object_dir(case_id)
    object_dir.mkdir(parents=True, exist_ok=True)
    path = _knowledge_object_path(case_id, item_id)
    path.write_text(json.dumps(payload, indent=2))
    return payload


def _projection_paths(case_id: str, item_id: str, tags: list[str]) -> list[Path]:
    normalized = set(tags)
    targets: list[Path] = []
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", item_id).strip("-") or "item"
    if "Protocol" in normalized:
        targets.append(LIBRARY_DIR / "protocols" / "promoted" / f"{slug}.md")
    if normalized & {"Detection", "Reusable Query"}:
        targets.append(LIBRARY_DIR / "experience" / "detections" / f"{slug}.md")
    if normalized & {"Detection Syntax", "SIEM Syntax", "Field Mapping", "Platform Quirk"}:
        targets.append(LIBRARY_DIR / "experience" / "detection-syntax" / f"{slug}.md")
    if normalized & {"Experience", "Heuristic", "Baseline / Normal", "False Positive Lesson", "Case Pattern", "Reusable"}:
        targets.append(LIBRARY_DIR / "experience" / "promoted" / f"{slug}.md")
    if normalized & {"API Answer", "Case-Specific", "Needs Review", "Stale"} or not targets:
        targets.append(LIBRARY_DIR / "cases" / case_id / "knowledge-promotions" / f"{slug}.md")
    unique: list[Path] = []
    seen: set[str] = set()
    for path in targets:
        marker = str(path)
        if marker not in seen:
            unique.append(path)
            seen.add(marker)
    return unique


def _write_projection_notes(case_id: str, item_id: str, payload: dict[str, Any]) -> list[str]:
    written: list[str] = []
    for path in _projection_paths(case_id, item_id, payload.get("tags") or []):
        path.parent.mkdir(parents=True, exist_ok=True)
        content = [
            f"# {payload.get('title') or item_id}",
            "",
            f"- **Case ID:** {case_id}",
            f"- **Knowledge Object ID:** {item_id}",
            f"- **Status:** {payload.get('status', 'promoted')}",
            f"- **Tags:** {', '.join(payload.get('tags') or []) or 'None'}",
        ]
        if payload.get("summary"):
            content.extend(["", "## Summary", payload["summary"]])
        if payload.get("rationale"):
            content.extend(["", "## OpenClaw recommendation", payload["rationale"]])
        if payload.get("comment"):
            content.extend(["", "## Human comment", payload["comment"]])
        if payload.get("source_kind"):
            content.extend(["", f"- **Source kind:** {payload['source_kind']}"])
        if payload.get("source_ref"):
            content.extend([f"- **Source ref:** {payload['source_ref']}"])
        path.write_text("\n".join(content).rstrip() + "\n")
        written.append(str(path.relative_to(LIBRARY_DIR)))
    return written


def _resolve_library_note(relative_path: str) -> Path:
    candidate = (LIBRARY_DIR / relative_path).resolve()
    library_root = LIBRARY_DIR.resolve()
    if library_root != candidate and library_root not in candidate.parents:
        raise HTTPException(status_code=400, detail="Invalid library path")
    if candidate.suffix.lower() != ".md":
        raise HTTPException(status_code=400, detail="Only markdown note paths are supported")
    return candidate


def _delete_case_runtime_data(case_id: str, *, unload_if_active: bool = True) -> dict[str, Any]:
    slug = slugify_case_id(case_id)
    deleted: list[dict[str, Any]] = []

    current = current_pcap()
    unloaded_pcap = None
    if current:
        try:
            active_case_id = ensure_case_for_pcap(current)["case_id"]
        except Exception:
            active_case_id = None
        if unload_if_active and active_case_id == slug and STATE_PATH.exists():
            try:
                STATE_PATH.unlink()
                unloaded_pcap = current
            except OSError:
                pass

    case_path = case_dir(slug)
    if case_path.exists():
        _delete_path(case_path, deleted)

    object_dir = _knowledge_object_dir(slug)
    if object_dir.exists():
        _delete_path(object_dir, deleted)
        _prune_empty_parents(object_dir, KNOWLEDGE_OBJECTS_DIR)

    index = load_case_index()
    index.cases = [entry for entry in index.cases if entry.case_id != slug]
    save_case_index(index)

    return {
        "case_id": slug,
        "unloaded_pcap": unloaded_pcap,
        "deleted": deleted,
        "deleted_count": len(deleted),
        "storage": _runtime_storage_summary(),
    }


def _library_tree_node(root: Path, *, base: Path) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    if not root.exists():
        return nodes
    for path in sorted(root.iterdir(), key=lambda item: (item.is_file(), item.name.lower())):
        if path.name.startswith("."):
            continue
        if path.name == "knowledge-objects":
            continue
        rel = str(path.relative_to(base))
        if path.is_dir():
            children = _library_tree_node(path, base=base)
            if children:
                nodes.append({"name": path.name, "path": rel, "kind": "dir", "children": children})
        else:
            if path.suffix.lower() == ".md":
                nodes.append({"name": path.name, "path": rel, "kind": "file"})
    return nodes


def _recommended_tags_for_item(item: dict[str, Any]) -> list[str]:
    source_kind = item.get("source_kind")
    recommended = item.get("recommended_tags") or []
    if recommended:
        return recommended
    if source_kind == "api_answer":
        return ["API Answer", "Needs Review"]
    if source_kind == "promotion_candidate":
        return ["Reusable", "Experience"]
    if source_kind == "save_pressure":
        return ["Needs Review", "Case-Specific"]
    return ["Needs Review"]


def _user_explicit_save_intent(message: str | None) -> bool:
    text = (message or "").lower()
    return any(phrase in text for phrase in (
        "save this",
        "save that",
        "promote this",
        "promote that",
        "keep this",
        "preserve this",
        "remember this",
        "capture this",
        "this should be saved",
        "this should be promoted",
        "add this to knowledge",
    ))


def _candidate_anchors(text: str) -> tuple[str, ...]:
    lowered = text.lower()
    anchors: list[str] = []
    anchors.extend(sorted(set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b", lowered))))
    anchors.extend(sorted(set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", lowered))))
    anchors.extend(sorted(set(re.findall(r"`([^`]+)`", text))))
    anchors.extend(sorted(set(re.findall(r"\/[a-z0-9._-]+", lowered))))
    for token in ("beacon", "wireshark", "zeek", "screenshot", "image parse failure", "modbus"):
        if token in lowered:
            anchors.append(token)
    seen: list[str] = []
    for item in anchors:
        if item and item not in seen:
            seen.append(item)
    return tuple(seen)


def _candidate_is_generic_case_noise(text: str) -> bool:
    lowered = text.lower().strip()
    generic_starts = (
        "potential periodic check-in pattern",
        "image parse failure should be preserved",
        "preserve that this is confirmed",
        "preserve that beacon evidence exists outside the screenshot",
        "preserve that no zeek",
        "keep the zeek-versus-wireshark visibility gap",
    )
    if lowered.startswith(generic_starts):
        return True
    if "if request timing proves regular" in lowered:
        return True
    return False


def _dedupe_candidate_texts(values: list[str], *, limit: int = 3) -> list[str]:
    kept: list[str] = []
    seen_keys: set[tuple[str, ...] | str] = set()
    for raw in values:
        text = (raw or "").strip()
        if not text or _candidate_is_generic_case_noise(text):
            continue
        anchors = _candidate_anchors(text)
        key: tuple[str, ...] | str = anchors if anchors else re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
        if key in seen_keys:
            continue
        seen_keys.add(key)
        kept.append(text)
        if len(kept) >= limit:
            break
    return kept


def _knowledge_queue(case_id: str) -> list[dict[str, Any]]:
    state = load_case_state(case_id)
    dismissed = set(state.get("dismissed_knowledge_items") or [])
    queue: list[dict[str, Any]] = []
    for index, text in enumerate(_dedupe_candidate_texts(state.get("promotion_candidates") or [], limit=3), start=1):
        queue.append({
            "item_id": f"promotion-candidate-{index}",
            "source_kind": "promotion_candidate",
            "title": f"Promotion candidate {index}",
            "summary": text,
            "rationale": "OpenClaw flagged this as something likely worth preserving beyond the current case.",
        })
    for index, text in enumerate(_dedupe_candidate_texts(state.get("save_pressure") or [], limit=1), start=1):
        queue.append({
            "item_id": f"save-pressure-{index}",
            "source_kind": "save_pressure",
            "title": f"Save-pressure item {index}",
            "summary": text,
            "rationale": "OpenClaw thinks this may be lost or under-documented if it is not captured deliberately.",
        })
    for question in state.get("api_questions") or []:
        if question.get("status") != "answered":
            continue
        queue.append({
            "item_id": question.get("id") or f"api-{len(queue)+1}",
            "source_kind": "api_answer",
            "title": question.get("question") or "Answered API question",
            "summary": question.get("helpful_answer_would") or question.get("pcap_evidence") or question.get("question"),
            "rationale": "Answered external questions often become durable protocol, detection, or syntax guidance if curated properly.",
            "source_ref": question.get("answer_path"),
        })
    if not queue:
        summary = ((state.get("evidence_snapshot") or {}).get("summary") or state.get("current_question") or "Capture this case summary deliberately if it matters later.")
        queue.append({
            "item_id": "case-summary-fallback",
            "source_kind": "case_summary",
            "title": "Current case summary",
            "summary": summary,
            "rationale": "This case does not yet have explicit promotion candidates, so PIRE is surfacing the current working summary as a starting point for knowledge curation.",
            "recommended_tags": ["Case-Specific", "Needs Review"],
        })
    enriched: list[dict[str, Any]] = []
    for item in queue:
        if item["item_id"] in dismissed:
            continue
        existing = _load_knowledge_object(case_id, item["item_id"]) or {}
        status = existing.get("status") or "proposed"
        if status in {"promoted", "rejected", "deleted"}:
            continue
        enriched.append({
            **item,
            "status": status,
            "comment": existing.get("comment") or "",
            "selected_tags": existing.get("tags") or _recommended_tags_for_item(item),
            "recommended_tags": _recommended_tags_for_item(item),
            "available_tags": KNOWLEDGE_TAGS,
            "destinations": existing.get("projection_paths") or [],
        })
    return enriched


def _knowledge_payload(case_id: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "queue": _knowledge_queue(case_id),
        "tree": _library_tree_node(LIBRARY_DIR, base=LIBRARY_DIR),
    }


@app.on_event("startup")
def startup() -> None:
    ensure_dirs()
    KNOWLEDGE_OBJECTS_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse({"ok": True})


@app.get("/api/status")
def status() -> JSONResponse:
    ensure_dirs()
    pcaps = list_pcaps()
    loaded = current_pcap()
    metadata = metadata_for_loaded(loaded)
    active_case = None
    zeek_summary = None
    if loaded:
        active_case = ensure_case_for_pcap(loaded)
        zeek_summary = safe_zeek_summary(loaded)
    return JSONResponse(
        {
            "connected": True,
            "title": "PIRE PCAP Ingest Read & Evaluate",
            "loaded_pcap": loaded,
            "active_case_id": active_case["case_id"] if active_case else None,
            "pcap_count": len(pcaps),
            "latest_metadata": metadata,
            "pcaps": pcaps[:200],
            "storage": _runtime_storage_summary(),
            "notes_path": str(DATA_DIR / "notes.md"),
            "openclaw": openclaw_status(),
            "zeek": zeek_summary,
        }
    )


@app.get("/api/pcap")
def pcap_details(pcap: str | None = None) -> JSONResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=404, detail="No PCAP is currently loaded")
    metadata = metadata_for_pcap(target)
    return JSONResponse({"pcap": target, "metadata": metadata})


@app.get("/api/pcap/download")
def download_pcap(pcap: str | None = None) -> FileResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=404, detail="No PCAP is currently loaded")
    try:
        pcap_path = resolve_pcap(target)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"PCAP not found: {target}")
    return FileResponse(path=pcap_path, filename=pcap_path.name, media_type="application/vnd.tcpdump.pcap")


@app.get("/api/overview")
def overview(pcap: str | None = None) -> JSONResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=404, detail="No PCAP is currently loaded")
    return JSONResponse(build_overview(target))


@app.get("/api/view/conversations")
def conversations_view(pcap: str | None = None, page: int = 1, page_size: int = 25, q: str = "", sort_by: str = "connections", sort_dir: str = "desc") -> JSONResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=404, detail="No PCAP is currently loaded")
    return JSONResponse({"pcap": target, **conversation_page(target, page=page, page_size=page_size, q=q, sort_by=sort_by, sort_dir=sort_dir)})


@app.get("/api/view/hosts")
def hosts_view(pcap: str | None = None, page: int = 1, page_size: int = 25, q: str = "", sort_by: str = "interestingness", sort_dir: str = "desc") -> JSONResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=404, detail="No PCAP is currently loaded")
    return JSONResponse({"pcap": target, **host_page(target, page=page, page_size=page_size, q=q, sort_by=sort_by, sort_dir=sort_dir)})


@app.get("/api/view/endpoints")
def endpoints_view(pcap: str | None = None, page: int = 1, page_size: int = 25, q: str = "", sort_by: str = "interestingness", sort_dir: str = "desc") -> JSONResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=404, detail="No PCAP is currently loaded")
    return JSONResponse({"pcap": target, **endpoint_page(target, page=page, page_size=page_size, q=q, sort_by=sort_by, sort_dir=sort_dir)})


@app.get("/api/zeek/summary")
def zeek_summary_view(pcap: str | None = None) -> JSONResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=404, detail="No PCAP is currently loaded")
    return JSONResponse(safe_zeek_summary(target))


@app.get("/api/zeek/log")
def zeek_log_view(name: str, pcap: str | None = None, limit: int = 80, q: str = "") -> JSONResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=404, detail="No PCAP is currently loaded")
    try:
        rows = zeek_log_rows(target, name, limit=limit, q=q)
        fields = zeek_log_fields(target, name)
        fallback_used = False
        merge_enabled_logs = {"http.log", "dns.log", "files.log", "ssl.log", "smtp.log", "smb_files.log", "smb_mapping.log", "dce_rpc.log", "ldap.log", "kerberos.log"}
        if name in merge_enabled_logs:
            fallback_rows = zeek_log_fallback_rows(target, name, q=q, limit=limit)
            if fallback_rows:
                rows = _merge_zeek_and_fallback_rows(rows, fallback_rows, limit=limit)
                fallback_used = True
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return JSONResponse({"pcap": target, "log": name, "rows": rows, "fields": fields, "fallback_used": fallback_used})


@app.post("/api/load")
def load_pcap(request: LoadRequest) -> JSONResponse:
    metadata = metadata_for_pcap(request.pcap)
    set_current_pcap(request.pcap)
    return JSONResponse({"loaded": request.pcap, "metadata": metadata, "overview": build_overview(request.pcap)})


@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)) -> JSONResponse:
    ensure_dirs()
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    if "/" in file.filename or "\\" in file.filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    destination = INCOMING_DIR / file.filename
    data = await file.read()
    destination.write_bytes(data)
    ingest_result = ingest_pcap(file.filename)
    metadata = metadata_for_pcap(file.filename)
    return JSONResponse(
        {
            "saved": True,
            "filename": file.filename,
            "path": str(destination),
            "size_bytes": destination.stat().st_size,
            "ingest": ingest_result,
            "metadata": metadata,
            "overview": build_overview(file.filename),
        }
    )


@app.post("/api/pcap/delete")
def delete_pcap(request: DeletePcapRequest) -> JSONResponse:
    try:
        result = _delete_pcap_runtime_data(request.pcap, delete_exports=request.delete_exports)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"PCAP not found: {request.pcap}")
    loaded_after = current_pcap()
    if not loaded_after and STATE_PATH.exists():
        try:
            STATE_PATH.unlink()
        except OSError:
            pass
    return JSONResponse(
        {
            "deleted_pcap": request.pcap,
            "loaded_pcap": loaded_after,
            "deleted_count": len(result["deleted"]),
            "bytes_freed": result["bytes_freed"],
            "deleted": result["deleted"],
            "storage": result["storage"],
        }
    )


@app.post("/api/case/delete")
def delete_case(request: DeleteCaseRequest) -> JSONResponse:
    target_case = request.case_id
    if not target_case:
        target = request.pcap or current_pcap()
        if not target:
            raise HTTPException(status_code=404, detail="No active case")
        target_case = ensure_case_for_pcap(target)["case_id"]
    result = _delete_case_runtime_data(target_case, unload_if_active=request.unload_if_active)
    return JSONResponse(result)


@app.post("/api/cleanup/exports")
def delete_all_exports() -> JSONResponse:
    result = _delete_all_exports()
    return JSONResponse(
        {
            "deleted_count": len(result["deleted"]),
            "bytes_freed": result["bytes_freed"],
            "deleted": result["deleted"],
            "storage": result["storage"],
        }
    )


@app.post("/api/cleanup/zeek-cache")
def prune_orphan_zeek_cache() -> JSONResponse:
    result = _prune_orphan_zeek_cache()
    return JSONResponse(
        {
            "deleted_count": len(result["deleted"]),
            "bytes_freed": result["bytes_freed"],
            "deleted": result["deleted"],
            "storage": result["storage"],
        }
    )


@app.get("/api/case")
def get_case(pcap: str | None = None, case_id: str | None = None) -> JSONResponse:
    target_case = case_id
    if not target_case:
        target = pcap or current_pcap()
        if not target:
            raise HTTPException(status_code=404, detail="No active case")
        target_case = ensure_case_for_pcap(target)["case_id"]
    return JSONResponse(case_snapshot(target_case))


@app.get("/api/knowledge")
def knowledge_view(pcap: str | None = None, case_id: str | None = None) -> JSONResponse:
    target_case = case_id
    if not target_case:
        target = pcap or current_pcap()
        if not target:
            raise HTTPException(status_code=404, detail="No active case")
        target_case = ensure_case_for_pcap(target)["case_id"]
    return JSONResponse(_knowledge_payload(target_case))


@app.get("/api/knowledge/note")
def knowledge_note(path: str) -> JSONResponse:
    note_path = _resolve_library_note(path)
    if not note_path.exists():
        raise HTTPException(status_code=404, detail=f"Knowledge note not found: {path}")
    return JSONResponse({
        "path": str(note_path.relative_to(LIBRARY_DIR)),
        "content": note_path.read_text(),
    })


@app.post("/api/knowledge/note")
def save_knowledge_note(request: KnowledgeNoteUpdateRequest) -> JSONResponse:
    note_path = _resolve_library_note(request.path)
    if not note_path.exists():
        raise HTTPException(status_code=404, detail=f"Knowledge note not found: {request.path}")
    note_path.write_text(request.content)
    return JSONResponse({
        "saved": True,
        "path": request.path,
    })


@app.delete("/api/knowledge/note")
def delete_knowledge_note(path: str) -> JSONResponse:
    note_path = _resolve_library_note(path)
    if not note_path.exists():
        raise HTTPException(status_code=404, detail=f"Knowledge note not found: {path}")
    note_path.unlink()
    _prune_empty_parents(note_path, LIBRARY_DIR)
    return JSONResponse({
        "deleted": True,
        "path": path,
    })


@app.post("/api/knowledge/object")
def save_knowledge_object(request: KnowledgeActionRequest) -> JSONResponse:
    target_case = request.case_id
    if not target_case:
        target = request.pcap or current_pcap()
        if not target:
            raise HTTPException(status_code=404, detail="No active case")
        target_case = ensure_case_for_pcap(target)["case_id"]

    if request.status == "deleted":
        _delete_knowledge_object(target_case, request.item_id)
        _set_knowledge_dismissed(target_case, request.item_id, True)
        return JSONResponse({
            "saved": None,
            "deleted": True,
            "knowledge": _knowledge_payload(target_case),
        })

    _set_knowledge_dismissed(target_case, request.item_id, False)
    payload = {
        "item_id": request.item_id,
        "source_kind": request.source_kind,
        "title": request.title,
        "summary": request.summary,
        "rationale": request.rationale,
        "tags": request.tags,
        "comment": request.comment,
        "status": request.status,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if existing := _load_knowledge_object(target_case, request.item_id):
        payload.setdefault("created_at", existing.get("created_at"))
    else:
        payload["created_at"] = payload["updated_at"]
    payload["projection_paths"] = _write_projection_notes(target_case, request.item_id, payload)
    saved = _save_knowledge_object(target_case, request.item_id, payload)
    return JSONResponse({
        "saved": saved,
        "knowledge": _knowledge_payload(target_case),
    })


@app.get("/api/ip-dossier")
def ip_dossier(ip: str, pcap: str | None = None, case_id: str | None = None) -> JSONResponse:
    target = pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
    target_case = case_id or ensure_case_for_pcap(target)["case_id"]
    return JSONResponse(build_ip_dossier_payload(target, target_case, ip))


@app.post("/api/ip-dossier/select")
def ip_dossier_select(request: DossierQuestionSelectRequest) -> JSONResponse:
    target = request.pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
    target_case = request.case_id or ensure_case_for_pcap(target)["case_id"]
    payload = build_ip_dossier_payload(target, target_case, request.ip)
    section = next((item for item in payload.get("sections", []) if item.get("id") == request.section_id), None)
    if not section:
        raise HTTPException(status_code=404, detail=f"Unknown dossier section: {request.section_id}")
    question = section.get("question")
    if not question:
        return JSONResponse({"created": False, "reason": "This section does not currently carry a suggested question.", "dossier": payload})
    created = add_api_questions(
        target_case,
        [
            {
                "question": question,
                "why_ask": section.get("why_ask"),
                "pcap_evidence": section.get("summary"),
                "experiential_knowledge": section.get("experience_snippet"),
                "protocol_knowledge": section.get("protocol_snippet"),
                "helpful_answer_would": section.get("helpful_answer_would"),
            }
        ],
    )
    return JSONResponse({"created": True, "question_result": created, "dossier": build_ip_dossier_payload(target, target_case, request.ip)})


@app.post("/api/ip-dossier/knowledge-action")
def ip_dossier_knowledge_action(request: DossierKnowledgeActionRequest) -> JSONResponse:
    target = request.pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
    target_case = request.case_id or ensure_case_for_pcap(target)["case_id"]
    payload = build_ip_dossier_payload(target, target_case, request.ip)
    section = next((item for item in payload.get("sections", []) if item.get("id") == request.section_id), None)
    if not section:
        raise HTTPException(status_code=404, detail=f"Unknown dossier section: {request.section_id}")
    kind = (request.kind or "").strip().lower()
    if kind not in {"browser", "api"}:
        raise HTTPException(status_code=400, detail="kind must be 'browser' or 'api'")
    action = build_knowledge_action(request.ip, section, kind=kind, line_index=request.line_index)
    saved = add_knowledge_action(
        target_case,
        {
            **action,
            "ip": request.ip,
            "section_id": request.section_id,
            "line_index": request.line_index,
        },
    )
    return JSONResponse({
        "created": True,
        "action": saved,
        "dossier": build_ip_dossier_payload(target, target_case, request.ip),
    })


@app.post("/api/retrieve")
def retrieve(request: RetrievalRequest) -> JSONResponse:
    target_case = request.case_id
    if not target_case:
        target = request.pcap or current_pcap()
        if not target:
            raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
        target_case = ensure_case_for_pcap(target)["case_id"]
    layered = retrieve_layered_knowledge(target_case, request.topic)
    return JSONResponse({"case_id": target_case, "topic": request.topic, "knowledge": layered})


@app.post("/api/questions")
def create_questions(request: QuestionCreateRequest) -> JSONResponse:
    target_case = request.case_id
    if not target_case:
        target = request.pcap or current_pcap()
        if not target:
            raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
        target_case = ensure_case_for_pcap(target)["case_id"]
    result = add_api_questions(target_case, request.questions)
    return JSONResponse(result)


@app.post("/api/questions/select")
def select_question(request: QuestionSelectRequest) -> JSONResponse:
    target_case = request.case_id
    if not target_case:
        target = request.pcap or current_pcap()
        if not target:
            raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
        target_case = ensure_case_for_pcap(target)["case_id"]
    try:
        result = select_api_question(target_case, request.question_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return JSONResponse(result)


@app.post("/api/questions/answer")
def answer_question(request: QuestionAnswerRequest) -> JSONResponse:
    target_case = request.case_id
    if not target_case:
        target = request.pcap or current_pcap()
        if not target:
            raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
        target_case = ensure_case_for_pcap(target)["case_id"]
    try:
        result = save_api_answer(
            target_case,
            request.question_id,
            answer_summary=request.answer_summary,
            answer_body=request.answer_body,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return JSONResponse(result)


@app.post("/api/chat")
def chat(request: ChatRequest) -> JSONResponse:
    target = request.pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
    started = time.perf_counter()
    logger.info("/api/chat start pcap=%s message=%r", target, request.message)
    try:
        payload = interpret_message(
            target,
            request.message,
            selected_knowledge=request.selected_knowledge,
            attachments=[attachment.model_dump() for attachment in (request.attachments or [])],
        )
    except FileNotFoundError as exc:
        logger.exception("/api/chat file_not_found pcap=%s elapsed=%.3fs", target, time.perf_counter() - started)
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        logger.exception("/api/chat runtime_error pcap=%s elapsed=%.3fs", target, time.perf_counter() - started)
        raise HTTPException(status_code=500, detail=str(exc))
    logger.info(
        "/api/chat complete pcap=%s elapsed=%.3fs mode=%s reply_chars=%s",
        target,
        time.perf_counter() - started,
        payload.get("mode"),
        len(payload.get("reply") or ""),
    )
    return JSONResponse(payload)


@app.post("/api/terminal")
def terminal(request: TerminalRequest) -> JSONResponse:
    target = request.pcap or current_pcap()
    if not target:
        raise HTTPException(status_code=400, detail="Load or upload a PCAP first")
    try:
        payload = run_terminal_command(target, request.command)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return JSONResponse(payload)


def metadata_for_loaded(loaded: str | None) -> dict[str, Any] | None:
    if not loaded:
        return None
    try:
        return metadata_for_pcap(loaded)
    except Exception:
        return None


def row_value(row: dict[str, str], *names: str) -> str:
    for name in names:
        if name in row and row[name]:
            return row[name]
    return ""


def preview_lines(rows: list[dict[str, str]], limit: int = 8) -> list[str]:
    lines: list[str] = []
    for row in rows[:limit]:
        frame = row_value(row, "frame.number") or "?"
        src = row_value(row, "ip.src") or "?"
        dst = row_value(row, "ip.dst") or "?"
        proto = row_value(row, "_ws.col.Protocol", "_ws.col.protocol") or "?"
        info = row_value(row, "_ws.col.Info", "_ws.col.info")
        lines.append(f"frame {frame}: {src} -> {dst} [{proto}] {info}".strip())
    return lines


def unique_pairs(rows: list[dict[str, str]], limit: int = 3) -> list[str]:
    seen: list[str] = []
    for row in rows:
        src = row_value(row, "ip.src") or "?"
        dst = row_value(row, "ip.dst") or "?"
        pair = f"{src} -> {dst}"
        if pair not in seen:
            seen.append(pair)
        if len(seen) >= limit:
            break
    return seen


def frame_numbers(rows: list[dict[str, str]], limit: int = 8) -> list[int]:
    values: list[int] = []
    for row in rows:
        raw = row_value(row, "frame.number")
        if raw and raw.isdigit():
            values.append(int(raw))
        if len(values) >= limit:
            break
    return values


TOPIC_FILTERS: dict[str, str] = {
    "http": "http",
    "dns": "dns",
    "smb": "smb",
    "kerberos": "kerberos",
    "ldap": "ldap",
    "icmp": "icmp",
    "dhcp": "dhcp",
    "snmp": "snmp",
    "smtp": "smtp",
    "opcua": "opcua || tcp.port == 4840",
    "modbus": "modbus",
    "dnp3": "dnp3",
    "bacnet": "bacnet",
    "profinet": "pn_rt || dce_rpc.cn_bind_to_uuid == e59f1bc2-7f75-4bb8-b4b1-9488bc6f43a1",
    "tls": "tls",
    "cotp": "cotp",
    "tpkt": "tpkt",
    "s7": "s7comm || cotp || tpkt || tcp.port == 102",
    "s7comm": "s7comm || cotp || tpkt || tcp.port == 102",
    "siemens": "s7comm || cotp || tpkt || tcp.port == 102",
}

TOPIC_ALIASES: dict[str, list[str]] = {
    "opc ua": ["opcua"],
    "modbus/tcp": ["modbus"],
    "s7comm": ["s7"],
    "siemens s7": ["s7"],
}

RELATION_HINTS: dict[str, list[str]] = {
    "cotp": ["tpkt", "s7"],
    "tpkt": ["cotp", "s7"],
    "s7": ["cotp", "tpkt"],
    "siemens": ["s7", "cotp", "tpkt"],
}

QUESTION_WORDS = ("what", "why", "how", "when", "where", "which", "can", "does", "is", "are", "should")
IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def hierarchy_frame_count(protocols: list[str], topic: str) -> int | None:
    prefixes = {
        "cotp": ["cotp frames:"],
        "tpkt": ["tpkt frames:"],
        "s7": ["s7comm frames:", "cotp frames:", "tpkt frames:"],
        "s7comm": ["s7comm frames:", "cotp frames:", "tpkt frames:"],
        "siemens": ["s7comm frames:", "cotp frames:", "tpkt frames:"],
    }.get(topic, [f"{topic} frames:"])
    for line in protocols:
        lowered = line.lower()
        for prefix in prefixes:
            if lowered.startswith(prefix):
                match = re.search(r"frames:(\d+)", lowered)
                if match:
                    return int(match.group(1))
    return None


def library_summary_text(knowledge: dict[str, list[dict[str, Any]]]) -> str:
    pieces: list[str] = []
    for label, key in [("protocol", "protocol"), ("experience", "experience"), ("current case", "current_case")]:
        count = len(knowledge.get(key, []))
        if count:
            pieces.append(f"{count} {label} note{'s' if count != 1 else ''}")
    if not pieces:
        return "No matching notes were found yet in the library layers."
    return "Library check: " + ", ".join(pieces) + "."


def first_snippet(items: list[dict[str, Any]] | None) -> str:
    if not items:
        return "None yet."
    return items[0].get("snippet") or items[0].get("title") or "None yet."


def build_knowledge_action(ip: str, section: dict[str, Any], *, kind: str, line_index: int | None = None) -> dict[str, Any]:
    key_lines = section.get("key_lines") or []
    selected_line = key_lines[line_index] if isinstance(line_index, int) and 0 <= line_index < len(key_lines) else None
    focus_text = selected_line or section.get("summary") or section.get("detail") or ip
    question = section.get("question") or f"What should we learn next about {ip}?"
    why_ask = section.get("why_ask") or "Improve the dossier with external knowledge."
    protocol = section.get("protocol_snippet") or "None yet."
    experience = section.get("experience_snippet") or "None yet."

    if kind == "browser":
        queries = [
            f'"{ip}" {section.get("label", "activity")} {focus_text}',
            f'"{ip}" {focus_text} threat intelligence',
            f'"{ip}" {section.get("label", "service")} analyst blog OR documentation',
        ]
        return {
            "kind": "browser",
            "title": f"Browser research plan for {ip} / {section.get('label', 'section')}",
            "summary": f"Use focused web research to separate notable behavior from benign background activity for {ip}.",
            "payload": {
                "selected_line": selected_line,
                "question": question,
                "why_ask": why_ask,
                "queries": queries,
                "review_checklist": [
                    "Look for infrastructure context, ownership, and role clues.",
                    "Look for service-normal explanations before treating the signal as malicious.",
                    "Prefer sources that help reduce false positives in future detections.",
                ],
            },
        }

    return {
        "kind": "api",
        "title": f"API enrichment plan for {ip} / {section.get('label', 'section')}",
        "summary": f"Use structured enrichment to sharpen the dossier and reduce analyst-noise risk for {ip}.",
        "payload": {
            "selected_line": selected_line,
            "question": question,
            "why_ask": why_ask,
            "targets": [
                {
                    "name": "VirusTotal or equivalent IP enrichment",
                    "purpose": "Reputation, tags, passive observations, and related infrastructure clues.",
                    "request_example": {"ip": ip, "focus": focus_text},
                },
                {
                    "name": "Shodan / Censys style service exposure lookup",
                    "purpose": "Validate whether the service picture matches the dossier role hypothesis.",
                    "request_example": {"ip": ip, "section": section.get("label")},
                },
                {
                    "name": "Internal asset / CMDB lookup",
                    "purpose": "Decide whether this IP is expected infrastructure, a managed endpoint, or unknown.",
                    "request_example": {"ip": ip, "need": "owner, hostname, role, environment"},
                },
            ],
            "evidence_bundle": {
                "selected_line": focus_text,
                "protocol_knowledge": protocol,
                "experiential_knowledge": experience,
            },
        },
    }


def build_ip_dossier_payload(pcap: str, case_id: str, ip: str) -> dict[str, Any]:
    endpoint = zeek_endpoint_activity(pcap, ip)
    profile = zeek_ip_profile(pcap, ip)
    layered = retrieve_layered_knowledge(case_id, ip)
    update_case_links(case_id, layered)
    state = case_snapshot(case_id)
    protocol_snippet = first_snippet(layered.get("protocol"))
    experience_snippet = first_snippet(layered.get("experience"))
    current_case_snippet = first_snippet(layered.get("current_case"))
    matches_by_log = profile.get("matches_by_log") or {}
    cross_logs = ", ".join(f"{name} ({details.get('count', 0)})" for name, details in sorted(matches_by_log.items())) or "No cross-log matches yet"
    top_service = (endpoint.get("top_services") or [{}])[0]
    top_peer = (endpoint.get("top_peers") or [{}])[0]
    verdict_key_lines = (profile.get("suspicion_reasons") or [])[:4] + (profile.get("benign_signals") or [])[:3]
    role_key_lines = [
        f"initiated {endpoint.get('initiated_count', 0)} connections",
        f"responded to {endpoint.get('responded_count', 0)} connections",
    ]
    service_key_lines = [f"{item.get('name')} ({item.get('count')})" for item in endpoint.get("top_services", [])[:6]]
    peer_key_lines = [f"{item.get('peer')} ({item.get('count')})" for item in endpoint.get("top_peers", [])[:8]]
    cross_log_key_lines = [f"{name} ({details.get('count', 0)})" for name, details in sorted(matches_by_log.items())[:8]]
    http_fallback_rows = profile.get("http_packet_fallback_rows") or []
    file_fallback_rows = profile.get("file_packet_fallback_rows") or []
    ssl_fallback_rows = profile.get("ssl_packet_fallback_rows") or []
    knowledge_key_lines = [
        f"Protocol: {protocol_snippet}",
        f"Experience: {experience_snippet}",
        f"Current case: {current_case_snippet}",
    ]
    if http_fallback_rows:
        fallback = http_fallback_rows[0]
        verdict_key_lines.insert(0, f"Recovered HTTP fallback: {fallback.get('method', 'HTTP')} {fallback.get('uri', '')} -> {fallback.get('status_code', '')} {fallback.get('resp_mime_types', '')}".strip())
        service_key_lines.insert(0, f"packet fallback HTTP: {fallback.get('host', 'n/a')} {fallback.get('uri', '')}".strip())
        cross_log_key_lines.insert(0, f"http.packet_fallback ({len(http_fallback_rows)})")
    if file_fallback_rows:
        file_row = file_fallback_rows[0]
        verdict_key_lines.insert(0, f"Recovered file/artifact fallback: {file_row.get('filename', 'artifact')} {file_row.get('mime_type', '')}".strip())
        cross_log_key_lines.insert(0, f"files.packet_fallback ({len(file_fallback_rows)})")
    if ssl_fallback_rows:
        ssl_row = ssl_fallback_rows[0]
        verdict_key_lines.insert(0, f"Recovered TLS fallback: {ssl_row.get('server_name', ssl_row.get('id.resp_h', 'tls'))} {ssl_row.get('version', '')} {ssl_row.get('cipher', '')}".strip())
        cross_log_key_lines.insert(0, f"ssl.packet_fallback ({len(ssl_fallback_rows)})")
    artifact_key_lines: list[str] = []
    for row in file_fallback_rows[:8]:
        line = f"file fallback: {row.get('filename', '')} {row.get('mime_type', '')} {row.get('uri', '')}".strip()
        if line and line not in artifact_key_lines:
            artifact_key_lines.append(line)
        if len(artifact_key_lines) >= 4:
            break
    for row in ssl_fallback_rows[:8]:
        line = f"TLS fallback: {row.get('server_name', row.get('id.resp_h', ''))} {row.get('version', '')} {row.get('cipher', '')}".strip()
        if line and line not in artifact_key_lines:
            artifact_key_lines.append(line)
        if len(artifact_key_lines) >= 8:
            break
    sections = [
        {
            "id": "verdict",
            "label": "Verdict",
            "mark": "★",
            "status": "review",
            "summary": f"{profile.get('suspicion', 'possibly').upper()} • score {profile.get('suspicion_score', 0)} • confidence {profile.get('confidence', 'low')}",
            "detail": profile.get("assessment_summary") or "No assessment summary yet.",
            "question": f"Given the current evidence for {ip}, which signals deserve analyst attention and which should be deprioritized as likely benign service behavior?",
            "why_ask": "This turns the dossier into a high-fidelity triage question instead of relying on one heuristic flag.",
            "helpful_answer_would": "A prioritized split between compelling detection leads and likely-benign byproducts.",
            "key_lines": verdict_key_lines,
            "protocol_snippet": protocol_snippet,
            "experience_snippet": experience_snippet,
        },
        {
            "id": "role",
            "label": "Role split",
            "mark": "↔",
            "status": "observed",
            "summary": f"initiated {endpoint.get('initiated_count', 0)} • responded {endpoint.get('responded_count', 0)}",
            "detail": endpoint.get("summary_text") or "No role summary yet.",
            "question": f"Is the client-vs-service role pattern for {ip} normal for the observed services, or does it suggest a more interesting pivot?",
            "why_ask": "Role often matters more than protocol presence when hunting for low-noise detections.",
            "helpful_answer_would": "A role-grounded explanation of whether this endpoint should be treated as infrastructure, client activity, or something unusual.",
            "key_lines": role_key_lines,
            "protocol_snippet": protocol_snippet,
            "experience_snippet": experience_snippet,
        },
        {
            "id": "services",
            "label": "Services",
            "mark": "◉",
            "status": "observed",
            "summary": f"top service {top_service.get('name', 'n/a')} ({top_service.get('count', 0)})",
            "detail": ", ".join(f"{item.get('name')} ({item.get('count')})" for item in endpoint.get("top_services", [])[:6]) or "No service data yet.",
            "question": f"Which service behaviors for {ip} are normal background activity, and which service-specific markers could support a compelling low-noise detection?",
            "why_ask": "Useful detections usually anchor to the service behavior that actually matters.",
            "helpful_answer_would": "A shortlist of service-specific anomalies worth inspecting or detecting on.",
            "key_lines": service_key_lines,
            "protocol_snippet": protocol_snippet,
            "experience_snippet": experience_snippet,
        },
        {
            "id": "peers",
            "label": "Peers",
            "mark": "◎",
            "status": "review",
            "summary": f"top peer {top_peer.get('peer', 'n/a')} ({top_peer.get('count', 0)}) • public peers {profile.get('public_peer_count', 0)}",
            "detail": ", ".join(f"{item.get('peer')} ({item.get('count')})" for item in endpoint.get("top_peers", [])[:8]) or "No peer data yet.",
            "question": f"Which peers talking to {ip} look like expected infrastructure relationships, and which peer relationships would actually justify a detection hypothesis?",
            "why_ask": "Peer patterns are often where false positives are eliminated.",
            "helpful_answer_would": "A clean split between expected adjacency and suspicious adjacency.",
            "key_lines": peer_key_lines,
            "protocol_snippet": protocol_snippet,
            "experience_snippet": experience_snippet,
        },
        {
            "id": "cross-logs",
            "label": "Cross logs",
            "mark": "#",
            "status": "review",
            "summary": cross_logs,
            "detail": profile.get("summary_text") or "No cross-log summary yet.",
            "question": f"Which cross-log records for {ip} best explain the activity, and which ones are the strongest candidates for a detection-quality lead?",
            "why_ask": "This is where weak packet impressions often become high-confidence pivots.",
            "helpful_answer_would": "The small set of logs or fields most worth drilling into next.",
            "key_lines": cross_log_key_lines,
            "protocol_snippet": protocol_snippet,
            "experience_snippet": experience_snippet,
        },
        {
            "id": "artifacts",
            "label": "Recovered artifacts",
            "mark": "✦",
            "status": "observed",
            "summary": f"file fallback {len(file_fallback_rows)} • tls fallback {len(ssl_fallback_rows)} • http fallback {len(http_fallback_rows)}",
            "detail": "Packet-derived artifacts that help compensate when Zeek log coverage is partial or missing.",
            "question": f"Which recovered packet-derived artifacts for {ip} are strong enough to drive the next pivot or detection idea?",
            "why_ask": "This keeps recovered evidence visible in the dossier instead of burying it only in raw log tables.",
            "helpful_answer_would": "A short list of recovered artifacts worth pivoting on next.",
            "key_lines": artifact_key_lines,
            "protocol_snippet": protocol_snippet,
            "experience_snippet": experience_snippet,
        },
        {
            "id": "knowledge",
            "label": "Library",
            "mark": "?",
            "status": "known",
            "summary": f"protocol: {len(layered.get('protocol', []))} • experience: {len(layered.get('experience', []))} • current case: {len(layered.get('current_case', []))}",
            "detail": f"Protocol: {protocol_snippet}\n\nExperience: {experience_snippet}\n\nCurrent case: {current_case_snippet}",
            "question": f"What specific missing knowledge about {ip} or its services should we fill next from external references so the dossier becomes more discriminating?",
            "why_ask": "This explicitly closes the knowledge loop instead of treating the dossier as a dead-end summary.",
            "helpful_answer_would": "A small number of targeted questions or searches that would materially improve the verdict.",
            "key_lines": knowledge_key_lines,
            "protocol_snippet": protocol_snippet,
            "experience_snippet": experience_snippet,
        },
    ]
    return {
        "pcap": pcap,
        "case_id": case_id,
        "ip": ip,
        "verdict": {
            "label": profile.get("suspicion", "possibly"),
            "score": profile.get("suspicion_score", 0),
            "confidence": profile.get("confidence", "low"),
            "reasons": profile.get("suspicion_reasons") or [],
            "benign_signals": profile.get("benign_signals") or [],
            "summary": profile.get("assessment_summary") or "No assessment summary yet.",
        },
        "sections": sections,
        "knowledge": layered,
        "api_questions": state.get("api_questions") or [],
        "knowledge_actions": [
            item for item in (state.get("knowledge_actions") or [])
            if item.get("ip") == ip
        ],
        "outstanding_gaps": state.get("outstanding_gaps") or [],
    }


def summarize_protocol_findings(protocol: str, rows: list[dict[str, str]]) -> str:
    if not rows:
        return f"I did not find matching {protocol} packets in the current summary pass."
    frames = [row_value(row, "frame.number") for row in rows if row_value(row, "frame.number")]
    pairs = unique_pairs(rows)
    sample = preview_lines(rows, limit=3)
    frame_text = ""
    if frames:
        frame_text = f" I found {len(rows)} matching packets in the current slice, starting at frame {frames[0]}"
        if len(frames) > 1:
            frame_text += f" and running through about frame {frames[-1]}"
        frame_text += "."
    pair_text = f" The main endpoint pairs in this slice are {', '.join(pairs)}." if pairs else ""
    sample_text = f" Example packets: {' | '.join(sample)}." if sample else ""
    return f"I scoped the read stage to {protocol}.{frame_text}{pair_text}{sample_text}"


def summarize_general_findings(pcap: str, rows: list[dict[str, str]], protocols: list[str]) -> str:
    filtered = [
        line for line in protocols
        if not line.startswith(("eth ", "ip ", "tcp ", "udp ", "icmp ", "igmp ", "data ", "tcp.segments "))
    ]
    highlights = ", ".join(filtered[:5] or protocols[:5]) if protocols else "no protocol hierarchy yet"
    sample = preview_lines(rows, limit=3)
    parsed = build_overview(pcap).get("metadata", {}).get("parsed", {})
    packet_count = parsed.get("number_of_packets", "unknown")
    duration = parsed.get("capture_duration", "unknown duration")
    sample_text = f" First examples: {' | '.join(sample)}." if sample else ""
    return (
        f"Quick first pass: this capture has {packet_count} packets over {duration}. "
        f"More interesting protocol-hierarchy entries include {highlights}.{sample_text} "
        "Ask a question about a protocol, frame, IP pair, or behavior and I’ll work the investigation loop instead of just dumping a summary."
    )


def normalize_topic(value: str) -> str:
    lowered = value.lower().strip()
    if lowered in TOPIC_FILTERS:
        return lowered
    for alias, targets in TOPIC_ALIASES.items():
        if alias in lowered:
            return targets[0]
    return lowered


def detect_topics(text: str) -> list[str]:
    found: list[str] = []
    lowered = text.lower()
    for alias, targets in TOPIC_ALIASES.items():
        if alias in lowered:
            for target in targets:
                if target not in found:
                    found.append(target)
    for topic in TOPIC_FILTERS:
        if topic in lowered and topic not in found:
            found.append(topic)
    return found


def related_topics(topics: list[str], text: str) -> list[str]:
    results = list(topics)
    lowered = text.lower()
    for topic in topics:
        for candidate in RELATION_HINTS.get(topic, []):
            if candidate not in results:
                results.append(candidate)
    if "siemens" in lowered and "s7" not in results:
        results.append("s7")
    return results


def topic_filter(topic: str) -> str | None:
    return TOPIC_FILTERS.get(normalize_topic(topic))


def is_direct_question(text: str) -> bool:
    lowered = text.lower().strip()
    if "what should we ask next" in lowered or "show me what we should ask next" in lowered or "what should we ask" in lowered:
        return False
    return "?" in lowered or lowered.startswith(QUESTION_WORDS) or " can i assume " in f" {lowered} "


def parse_ask_sequence(text: str) -> list[int]:
    lowered = text.lower().strip()
    if not lowered.startswith("ask"):
        return []
    payload = lowered[3:].strip()
    if not payload:
        return []
    numbers: list[int] = []
    for part in [p.strip() for p in re.split(r"\bthen\b|,", payload) if p.strip()]:
        range_match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
        if range_match:
            start = int(range_match.group(1))
            end = int(range_match.group(2))
            step = 1 if end >= start else -1
            numbers.extend(list(range(start, end + step, step)))
            continue
        if part.isdigit():
            numbers.append(int(part))
    return numbers


def safe_summary_rows(pcap: str, protocol: str | None = None, limit: int = 60) -> list[dict[str, str]]:
    try:
        return summary_rows(pcap, protocol=protocol, limit=limit)
    except Exception:
        return []


def safe_protocol_hierarchy(pcap: str, limit: int = 12) -> list[str]:
    try:
        return protocol_hierarchy(pcap, limit=limit)
    except Exception:
        return []


def extract_ips(text: str) -> list[str]:
    seen: list[str] = []
    for match in IP_PATTERN.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


def safe_endpoint_rows(pcap: str, ip: str, protocol: str | None = None, limit: int = 80) -> list[dict[str, str]]:
    try:
        return endpoint_rows(pcap, ip=ip, protocol=protocol, limit=limit)
    except Exception:
        return []


def gather_topic_evidence(pcap: str, topic: str, broad_protocols: list[str] | None = None) -> dict[str, Any]:
    filt = topic_filter(topic)
    rows = safe_summary_rows(pcap, protocol=filt, limit=60) if filt else []
    broad_protocols = broad_protocols or []
    hierarchy_count = hierarchy_frame_count(broad_protocols, topic)
    effective_count = len(rows) if rows else (hierarchy_count or 0)
    return {
        "topic": topic,
        "filter": filt,
        "rows": rows,
        "frames": frame_numbers(rows),
        "endpoints": unique_pairs(rows),
        "preview": preview_lines(rows, limit=4),
        "count": effective_count,
        "row_count": len(rows),
        "hierarchy_count": hierarchy_count,
    }


def gather_investigation_context(pcap: str, case_id: str, text: str) -> dict[str, Any]:
    topics = detect_topics(text)
    expanded_topics = related_topics(topics, text)
    broad_protocols = safe_protocol_hierarchy(pcap, limit=12)
    evidence = {topic: gather_topic_evidence(pcap, topic, broad_protocols=broad_protocols) for topic in expanded_topics}
    ips = extract_ips(text)
    for ip in ips:
        key = f"endpoint:{ip}"
        rows = safe_endpoint_rows(pcap, ip=ip, limit=80)
        zeek = zeek_endpoint_activity(pcap, ip)
        zeek_profile = zeek_ip_profile(pcap, ip)
        evidence[key] = {
            "topic": key,
            "filter": f"ip.addr == {ip}",
            "rows": rows,
            "frames": frame_numbers(rows),
            "endpoints": unique_pairs(rows),
            "preview": preview_lines(rows, limit=6),
            "count": len(rows) or zeek.get("conn_count", 0),
            "row_count": len(rows),
            "hierarchy_count": None,
            "ip": ip,
            "zeek": zeek,
            "zeek_profile": zeek_profile,
        }
    main_topic = topics[0] if topics else (f"endpoint:{ips[0]}" if ips else None)
    layered = retrieve_layered_knowledge(case_id, topics[0] if topics else (ips[0] if ips else "general"))
    update_case_links(case_id, layered)
    current_state = load_case_state(case_id)
    return {
        "case_id": case_id,
        "text": text,
        "main_topic": main_topic,
        "topics": expanded_topics,
        "ips": ips,
        "knowledge": layered,
        "broad_protocols": broad_protocols,
        "evidence": evidence,
        "current_state": current_state,
    }


def evidence_summary_lines(context: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for topic in context["topics"][:3]:
        item = context["evidence"].get(topic) or {}
        if item.get("count"):
            frame_text = ", ".join(str(frame) for frame in item.get("frames", [])[:4]) or "no frame numbers"
            endpoint_text = "; endpoints: " + ", ".join(item.get("endpoints", [])[:2]) if item.get("endpoints") else ""
            lines.append(f"{topic}: {item['count']} matching packets; frames {frame_text}{endpoint_text}")
    for ip in context.get("ips", [])[:2]:
        item = context["evidence"].get(f"endpoint:{ip}") or {}
        if item.get("count"):
            frame_text = ", ".join(str(frame) for frame in item.get("frames", [])[:4]) or "no frame numbers"
            endpoint_text = "; peers: " + ", ".join(item.get("endpoints", [])[:3]) if item.get("endpoints") else ""
            zeek_text = ""
            if item.get("zeek", {}).get("conn_count"):
                zeek_text = f"; Zeek connections: {item['zeek']['conn_count']}"
            profile = item.get("zeek_profile") or {}
            suspicion_text = f"; suspicion: {profile.get('suspicion')}" if profile.get("suspicion") else ""
            lines.append(f"endpoint {ip}: {item['count']} matching packets; frames {frame_text}{endpoint_text}{zeek_text}{suspicion_text}")
    if not lines:
        lines.append("No targeted packet evidence matched the current topic filters yet.")
    return lines


def propose_api_questions(context: dict[str, Any]) -> list[dict[str, Any]]:
    topic = context.get("main_topic") or "this traffic"
    evidence_lines = evidence_summary_lines(context)
    evidence_text = evidence_lines[0]
    protocol_note = context["knowledge"].get("protocol", [])
    experience_note = context["knowledge"].get("experience", [])
    protocol_text = protocol_note[0]["snippet"] if protocol_note else "None yet."
    experience_text = experience_note[0]["snippet"] if experience_note else "None yet."
    questions = [
        {
            "question": f"What protocol markers would confirm whether the observed {topic} traffic is actually what we think it is?",
            "why_ask": "This reduces the risk of over-claiming protocol identity from one layer or artifact alone.",
            "pcap_evidence": evidence_text,
            "experiential_knowledge": experience_text,
            "protocol_knowledge": protocol_text,
            "helpful_answer_would": "A short list of confirming indicators to verify against the capture.",
        },
        {
            "question": f"Which frames or service patterns in this {topic} traffic are most worth checking next for normal-vs-notable behavior?",
            "why_ask": "This helps move from identification into meaningful investigation.",
            "pcap_evidence": evidence_text,
            "experiential_knowledge": experience_text,
            "protocol_knowledge": protocol_text,
            "helpful_answer_would": "A prioritized next-step inspection plan tied to packet evidence.",
        },
    ]
    return questions


def ensure_persisted_questions(case_id: str, questions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    state = load_case_state(case_id)
    existing = state.get("api_questions") or []
    existing_by_question = {item.get("question"): item for item in existing}
    active_ids: list[str] = []
    new_questions = [question for question in questions if question.get("question") not in existing_by_question]
    if new_questions:
        add_api_questions(case_id, new_questions)
        state = load_case_state(case_id)
        existing = state.get("api_questions") or []
        existing_by_question = {item.get("question"): item for item in existing}
    for question in questions:
        existing_item = existing_by_question.get(question.get("question"))
        if existing_item and existing_item.get("id"):
            active_ids.append(existing_item["id"])
    state["active_question_ids"] = active_ids
    save_case_state(case_id, state)
    indexed = {item.get("id"): item for item in state.get("api_questions") or []}
    ordered = [indexed[qid] for qid in active_ids if qid in indexed]
    return ordered, active_ids


def synthesize_direct_answer(context: dict[str, Any]) -> tuple[str, str]:
    text = context["text"].lower()
    evidence = context["evidence"]
    main_topic = context.get("main_topic") or "the current topic"
    cotp = evidence.get("cotp", {})
    tpkt = evidence.get("tpkt", {})
    s7 = evidence.get("s7", {}) or evidence.get("s7comm", {})

    if isinstance(main_topic, str) and main_topic.startswith("endpoint:"):
        item = evidence.get(main_topic, {})
        ip = item.get("ip") or main_topic.split(":", 1)[1]
        zeek = item.get("zeek", {})
        profile = item.get("zeek_profile") or {}
        suspicion = profile.get("suspicion") or "possibly"
        suspicion_reasons = profile.get("suspicion_reasons") or []
        cross_log = profile.get("matches_by_log") or {}
        cross_log_text = ""
        if cross_log:
            cross_log_text = " Cross-log hits: " + ", ".join(f"{name} ({details.get('count', 0)})" for name, details in sorted(cross_log.items())) + "."
        reason_text = ""
        if suspicion_reasons:
            reason_text = " Why possibly suspicious: " + "; ".join(suspicion_reasons[:4]) + "."
        if item.get("row_count"):
            role_text = ""
            if zeek.get("initiated_count") or zeek.get("responded_count"):
                if (zeek.get("responded_count") or 0) > (zeek.get("initiated_count") or 0):
                    role_text = f" In this capture, {ip} looks more like a responding/service-side endpoint than a client."
                elif (zeek.get("initiated_count") or 0) > (zeek.get("responded_count") or 0):
                    role_text = f" In this capture, {ip} looks more like an initiating/client-side endpoint."
            return (
                f"Bottom line: suspiciousness for {ip} is {suspicion}.{role_text}",
                "Current-case evidence: "
                + summarize_protocol_findings(f"endpoint {ip}", item.get("rows", []))
                + (f" {zeek.get('summary_text')}" if zeek.get("summary_text") else "")
                + cross_log_text
                + reason_text
                + " Protocol / experience check: "
                + library_summary_text(context["knowledge"]),
            )
        if zeek.get("conn_count"):
            return (
                f"Bottom line: suspiciousness for {ip} is {suspicion}. I do not have a strong tshark packet slice, but Zeek clearly shows activity for it.",
                "Current-case evidence: " + zeek.get("summary_text", "") + cross_log_text + reason_text + " Protocol / experience check: " + library_summary_text(context["knowledge"]),
            )
        return (
            f"Bottom line: I do not currently find activity for {ip} in this capture.",
            "Current-case evidence: the direct packet slice returned zero rows, and Zeek conn.log also did not show activity for that IP in this PCAP. "
            + library_summary_text(context["knowledge"]),
        )

    if "assume" in text and ("cotp" in text or main_topic == "cotp") and ("s7" in text or "siemens" in text):
        answer = "No — COTP alone is not enough to assume Siemens S7 traffic."
        detail = [
            "COTP can appear as part of ISO-on-TCP stacks more broadly, so it is not uniquely Siemens S7 by itself.",
        ]
        if cotp.get("count"):
            detail.append(f"In this capture, I found COTP evidence in {cotp['count']} packets with frames such as {', '.join(str(f) for f in cotp.get('frames', [])[:4]) or 'none listed'}.")
        if tpkt.get("count"):
            detail.append(f"I also found TPKT evidence in {tpkt['count']} packets.")
        else:
            detail.append("I did not yet find separate TPKT evidence in the current targeted slice.")
        if s7.get("count"):
            detail.append(f"I found S7-related evidence in {s7['count']} packets, which strengthens the S7 hypothesis but still deserves frame-level confirmation.")
        else:
            detail.append("I did not yet find direct S7-specific evidence in the current targeted slice, so calling it Siemens S7 from COTP alone would be too strong.")
        detail.append(library_summary_text(context["knowledge"]))
        return answer, " ".join(detail)

    topic = main_topic
    item = evidence.get(topic or "", {}) if topic else {}
    if topic and item.get("count"):
        answer = f"I investigated your question against the {topic} traffic in the current capture."
        detail = []
        if item.get("rows"):
            detail.append(summarize_protocol_findings(topic, item.get("rows", [])))
        elif item.get("hierarchy_count"):
            detail.append(
                f"I do have capture evidence for {topic}: the protocol hierarchy shows about {item['hierarchy_count']} matching frames, even though the narrower row-level extraction still needs hardening for this protocol family."
            )
        detail.append(library_summary_text(context["knowledge"]))
        if context["knowledge"].get("protocol"):
            detail.append(f"Protocol note: {context['knowledge']['protocol'][0].get('snippet')}")
        if context["knowledge"].get("experience"):
            detail.append(f"Experiential note: {context['knowledge']['experience'][0].get('snippet')}")
        return answer, " ".join(detail)

    hierarchy_hits = []
    for topic_name, item in evidence.items():
        if item.get("hierarchy_count"):
            hierarchy_hits.append(f"{topic_name}: {item['hierarchy_count']} frames in protocol hierarchy")
    if hierarchy_hits:
        return (
            "I treated that as a real investigation question and checked the current capture plus the library layers.",
            "I do have protocol-hierarchy evidence, but the narrower packet extraction for this protocol family still needs hardening. "
            + "Current evidence: " + "; ".join(hierarchy_hits[:3]) + ". "
            + library_summary_text(context["knowledge"]),
        )

    return (
        "I treated that as a real investigation question and checked the current capture plus the library layers.",
        "I do not yet have enough targeted packet evidence to answer confidently from the current slice alone. "
        + library_summary_text(context["knowledge"]),
    )


def selection_response(pcap: str, case_id: str, indices: list[int]) -> dict[str, Any]:
    state = load_case_state(case_id)
    questions = state.get("api_questions") or []
    active_ids = state.get("active_question_ids") or []
    if active_ids:
        index_map = {item.get("id"): item for item in questions}
        ordered_questions = [index_map[qid] for qid in active_ids if qid in index_map]
    else:
        ordered_questions = questions
    chosen: list[dict[str, Any]] = []
    for index in indices:
        if 1 <= index <= len(ordered_questions):
            chosen.append(ordered_questions[index - 1])
    if not chosen:
        return {
            "mode": "question-select",
            "reply": "I could not match that selection to the current saved API questions.",
            "overview": build_overview(pcap),
            "case": case_snapshot(case_id),
        }

    answer_blocks: list[str] = []
    for ordinal, question in enumerate(chosen, start=1):
        select_api_question(case_id, question["id"])
        context = gather_investigation_context(pcap, case_id, question.get("question", ""))
        short_answer, detail = synthesize_direct_answer(context)
        save_api_answer(case_id, question["id"], answer_summary=short_answer, answer_body=detail)
        answer_blocks.append(f"Question {ordinal}: {question.get('question','Untitled question')}\n{short_answer}\n{detail}")

    record_investigation_turn(
        case_id,
        pcap_path=pcap,
        user_message=f"ask {' then '.join(str(i) for i in indices)}",
        summary="Answered selected saved API questions.",
        observation="Executed the selected API-question workflow against current evidence and knowledge.",
        next_step="Discuss the returned answers or ask another question grounded in the current capture.",
    )
    return {
        "mode": "question-select",
        "reply": "\n\n".join(answer_blocks) + "\n\nWe can now discuss these answers, ask another saved question, or return to the main investigation thread.",
        "overview": build_overview(pcap),
        "case": case_snapshot(case_id),
    }


def apply_openclaw_case_update(case_id: str, payload: dict[str, Any], *, focus: str | None = None, user_message: str | None = None) -> dict[str, Any]:
    state = load_case_state(case_id)
    if focus:
        state["current_focus"] = {"type": "topic", "value": focus}
    if payload.get("summary"):
        state.setdefault("evidence_snapshot", {})["summary"] = payload.get("summary")
    if payload.get("next_step"):
        state["last_recommended_next_step"] = payload.get("next_step")
    if payload.get("focus"):
        state["current_question"] = payload.get("focus")
    existing_promotions = state.get("promotion_candidates") or []
    state["promotion_candidates"] = _dedupe_candidate_texts(existing_promotions + (payload.get("promotion_candidates") or []), limit=3)
    existing_save_pressure = state.get("save_pressure") or []
    if _user_explicit_save_intent(user_message):
        state["save_pressure"] = _dedupe_candidate_texts(existing_save_pressure + (payload.get("save_pressure") or []), limit=1)
    else:
        state["save_pressure"] = []
    if payload.get("api_questions"):
        api_questions = state.get("api_questions") or []
        desired = [item.get("question") for item in payload.get("api_questions") or []]
        active_ids: list[str] = []
        for desired_question in desired:
            for item in api_questions:
                if item.get("question") == desired_question and item.get("id") not in active_ids:
                    active_ids.append(item.get("id"))
                    break
        if active_ids:
            state["active_question_ids"] = active_ids
    return save_case_state(case_id, state)


def format_api_question_block(case: dict[str, Any]) -> str:
    questions = case.get("api_questions") or []
    active_ids = case.get("active_question_ids") or []
    if active_ids:
        index_map = {item.get("id"): item for item in questions}
        ordered = [index_map[qid] for qid in active_ids if qid in index_map]
    else:
        ordered = questions
    proposed = [item for item in ordered if item.get("status") in {"proposed", "selected", None}]
    if not proposed:
        return ""
    lines = ["", "Proposed next questions:"]
    for idx, item in enumerate(proposed, start=1):
        lines.append(f"{idx}. {item.get('question')}")
        if item.get("pcap_evidence"):
            lines.append(f"   - PCAP evidence: {item.get('pcap_evidence')}")
        if item.get("protocol_knowledge"):
            lines.append(f"   - Protocol knowledge: {item.get('protocol_knowledge')}")
        if item.get("experiential_knowledge"):
            lines.append(f"   - Experiential knowledge: {item.get('experiential_knowledge')}")
    lines.append("Say: ask 1, ask 1-3, or 1 then 5 then 2.")
    return "\n".join(lines)


def compose_openclaw_reply(payload: dict[str, Any], case: dict[str, Any]) -> str:
    parts: list[str] = []
    reply = (payload.get("reply") or "").strip()
    if reply:
        parts.append(reply)
    observation = (payload.get("observation") or "").strip()
    interpretation = (payload.get("interpretation") or "").strip()
    next_step = (payload.get("next_step") or "").strip()
    if observation:
        parts.append(f"Current-case evidence: {observation}")
    if interpretation:
        parts.append(f"Interpretation / uncertainty: {interpretation}")
    if next_step:
        parts.append(f"Best next move: {next_step}")
    question_block = format_api_question_block(case)
    if question_block:
        parts.append(question_block)
    return "\n\n".join(part for part in parts if part)


def interpret_message(pcap: str, message: str, selected_knowledge: dict[str, Any] | None = None, attachments: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    text = message.strip()
    attachments = attachments or []
    if not text and attachments:
        count = len(attachments)
        text = (
            f"Please inspect the attached screenshot{'s' if count != 1 else ''} in the context of the current PCAP and case. "
            "If the screenshot is visible, describe what stands out and connect it to the investigation. "
            "If it is not visually available, say that briefly and still suggest the next narrowest useful move from the current packet evidence."
        )
    lowered = text.lower()
    set_current_pcap(pcap)
    case_info = ensure_case_for_pcap(pcap)
    case_id = case_info["case_id"]

    ask_indices = parse_ask_sequence(text)
    if ask_indices:
        return selection_response(pcap, case_id, ask_indices)

    if lowered == "next":
        rows = safe_summary_rows(pcap, limit=40)
        reply = "Here is another bounded slice from the current capture. If this starts to look interesting, I can narrow immediately by protocol, frame, or IP pair."
        record_investigation_turn(
            case_id,
            pcap_path=pcap,
            user_message=text,
            summary=reply,
            observation="Pulled another bounded summary slice for review.",
            frames=frame_numbers(rows),
            endpoints=unique_pairs(rows),
            next_step="Narrow by protocol, frame, or IP pair if this slice looks interesting.",
        )
        return {
            "mode": "next",
            "reply": reply,
            "rows": rows,
            "terminal_command": f"pire summary {pcap}",
            "overview": build_overview(pcap),
            "preview": preview_lines(rows),
            "case": case_snapshot(case_id),
            "investigation_trace": ["Loaded current case", "Pulled next bounded slice"],
        }

    frame_match = re.search(r"frame\s+(\d+)", lowered)
    if frame_match:
        frame = int(frame_match.group(1))
        rows = around_rows(pcap, frame=frame, before=20, after=20)
        reply = f"I pulled the packets around frame {frame}. I updated the timeline tab to that local window, and if you want I can now tighten the window or follow the related IP pair."
        record_investigation_turn(
            case_id,
            pcap_path=pcap,
            user_message=text,
            summary=f"Focused on the local window around frame {frame}.",
            observation=f"Reviewed the packet window around frame {frame}.",
            interpretation="This is a local pivot window for packet-grounded investigation.",
            frames=frame_numbers(rows) or [frame],
            endpoints=unique_pairs(rows),
            next_step="Tighten the window further or follow the most relevant IP pair from this frame pivot.",
        )
        return {
            "mode": "around",
            "reply": reply,
            "rows": rows,
            "terminal_command": f"pire around {pcap} --frame {frame} --before 20 --after 20",
            "overview": build_overview(pcap),
            "preview": preview_lines(rows),
            "case": case_snapshot(case_id),
            "investigation_trace": ["Loaded current case", f"Pivoted to frame {frame}"],
        }

    export_match = re.search(r"export\s+frames?\s+(\d+)\s*[-:]\s*(\d+)", lowered)
    if export_match:
        start = int(export_match.group(1))
        end = int(export_match.group(2))
        out_path = export_frame_range(pcap, start=start, end=end)
        reply = f"Done. I exported frames {start}-{end} to {out_path.name}."
        record_investigation_turn(
            case_id,
            pcap_path=pcap,
            user_message=text,
            summary=f"Exported frames {start}-{end} for reduced analysis.",
            observation=f"Created a reduced export covering frames {start}-{end}.",
            frames=[start, end],
            next_step="Inspect the reduced export or continue narrowing with another frame/pair pivot.",
        )
        return {
            "mode": "export",
            "reply": reply,
            "terminal_command": f"pire export-frames {pcap} --start {start} --end {end}",
            "export_path": str(out_path),
            "overview": build_overview(pcap),
            "case": case_snapshot(case_id),
            "investigation_trace": ["Loaded current case", f"Exported frames {start}-{end}"],
        }

    pair_match = re.search(r"(?:inspect|pair|between|follow).*?\b(\d{1,3}(?:\.\d{1,3}){3})\b.*?\b(\d{1,3}(?:\.\d{1,3}){3})\b", lowered)
    if pair_match:
        src = pair_match.group(1)
        dst = pair_match.group(2)
        rows = pair_rows(pcap, src=src, dst=dst, limit=80)
        reply = f"I pulled traffic between {src} and {dst}. If you want, we can further scope it to a protocol such as http or smb."
        record_investigation_turn(
            case_id,
            pcap_path=pcap,
            user_message=text,
            summary=f"Focused on traffic between {src} and {dst}.",
            observation=f"Reviewed the IP pair {src} <-> {dst}.",
            interpretation="This pair pivot can now be narrowed by protocol or frame window.",
            frames=frame_numbers(rows),
            endpoints=unique_pairs(rows) or [f"{src} -> {dst}"],
            next_step="Narrow this pair by protocol or inspect a specific frame from the pair timeline.",
        )
        return {
            "mode": "pair",
            "reply": reply,
            "rows": rows,
            "terminal_command": f"pire pair {pcap} --src {src} --dst {dst}",
            "overview": build_overview(pcap),
            "preview": preview_lines(rows),
            "case": case_snapshot(case_id),
            "investigation_trace": ["Loaded current case", f"Pivoted to pair {src} and {dst}"],
        }

    stage_started = time.perf_counter()
    context = gather_investigation_context(pcap, case_id, text)
    if selected_knowledge:
        context["selected_knowledge"] = selected_knowledge
        current_state = context.setdefault("current_state", {})
        current_state["selected_knowledge"] = selected_knowledge
    logger.info(
        "interpret_message context_ready case_id=%s elapsed=%.3fs main_topic=%s topics=%s evidence_counts=%s",
        case_id,
        time.perf_counter() - stage_started,
        context.get("main_topic"),
        context.get("topics"),
        {topic: (details or {}).get("count") for topic, details in (context.get("evidence") or {}).items()},
    )
    trace = [
        "Checked current case state",
        "Checked library for topic-specific notes",
        "Collected targeted packet evidence",
        "Separated current-case, experiential, and protocol knowledge",
    ]

    primary_rows: list[dict[str, str]] = []
    if context.get("main_topic"):
        primary_rows = context["evidence"].get(context["main_topic"], {}).get("rows", [])
    elif context.get("ips"):
        primary_rows = context["evidence"].get(f"endpoint:{context['ips'][0]}", {}).get("rows", [])

    if context.get("ips") and not context.get("topics"):
        short_answer, detail = synthesize_direct_answer(context)
        endpoint_key = f"endpoint:{context['ips'][0]}"
        endpoint_item = context["evidence"].get(endpoint_key, {})
        zeek_preview = (endpoint_item.get("zeek") or {}).get("preview", [])
        response_rows = primary_rows or zeek_preview
        record_investigation_turn(
            case_id,
            pcap_path=pcap,
            user_message=text,
            focus=context.get("main_topic"),
            summary=short_answer,
            observation=detail,
            interpretation="Used packet and Zeek endpoint evidence for a direct IP-behavior answer.",
            frames=frame_numbers(primary_rows),
            endpoints=unique_pairs(primary_rows) or [context['ips'][0]],
            next_step="Narrow to a peer, protocol, or frame window if you want to dig deeper.",
        )
        return {
            "mode": "endpoint-direct",
            "reply": f"{short_answer} {detail}".strip(),
            "rows": response_rows,
            "overview": build_overview(pcap),
            "preview": preview_lines(primary_rows) if primary_rows else [],
            "focus_ip": context["ips"][0],
            "dossier": build_ip_dossier_payload(pcap, case_id, context["ips"][0]),
            "case": case_snapshot(case_id),
            "investigation_trace": trace + ["Used Zeek endpoint summary for direct IP behavior read"],
        }

    stage_started = time.perf_counter()
    overview = build_overview(pcap)
    case = case_snapshot(case_id)
    logger.info(
        "interpret_message prompt_inputs_ready case_id=%s elapsed=%.3fs overview_protocols=%s timeline_rows=%s api_questions=%s",
        case_id,
        time.perf_counter() - stage_started,
        len(overview.get("top_protocols") or []),
        len(overview.get("timeline_preview") or []),
        len(case.get("api_questions") or []),
    )
    stage_started = time.perf_counter()
    openclaw_payload = ask_openclaw(
        pcap=pcap,
        user_message=text,
        case=case,
        context=context,
        overview=overview,
        attachments=attachments,
    )

    logger.info(
        "interpret_message openclaw_ready case_id=%s elapsed=%.3fs mode=%s trace_steps=%s api_questions=%s",
        case_id,
        time.perf_counter() - stage_started,
        openclaw_payload.get("mode"),
        len(openclaw_payload.get("investigation_trace") or []),
        len(openclaw_payload.get("api_questions") or []),
    )

    if openclaw_payload.get("api_questions"):
        add_api_questions(case_id, openclaw_payload["api_questions"])

    record_investigation_turn(
        case_id,
        pcap_path=pcap,
        user_message=text,
        focus=openclaw_payload.get("focus") or context.get("main_topic"),
        summary=openclaw_payload.get("summary") or " ".join(evidence_summary_lines(context)),
        observation=openclaw_payload.get("observation") or f"Investigated the user's question about {context.get('main_topic') or 'the current topic'}.",
        interpretation=openclaw_payload.get("interpretation") or "OpenClaw advanced the active PIRE investigation.",
        frames=frame_numbers(primary_rows),
        endpoints=unique_pairs(primary_rows),
        gaps=openclaw_payload.get("gaps") or [],
        next_step=openclaw_payload.get("next_step") or "Continue the active PIRE investigation.",
    )
    apply_openclaw_case_update(case_id, openclaw_payload, focus=openclaw_payload.get("focus") or context.get("main_topic"), user_message=text)
    updated_case = case_snapshot(case_id)
    final_reply = compose_openclaw_reply(openclaw_payload, updated_case)

    return {
        "mode": openclaw_payload.get("mode", "direct-question"),
        "reply": final_reply or openclaw_payload.get("reply", "OpenClaw returned no reply."),
        "rows": primary_rows,
        "overview": build_overview(pcap),
        "preview": preview_lines(primary_rows),
        "focus_ip": context["ips"][0] if context.get("ips") else None,
        "dossier": build_ip_dossier_payload(pcap, case_id, context["ips"][0]) if context.get("ips") else None,
        "knowledge": context["knowledge"],
        "case": updated_case,
        "investigation_trace": trace + (openclaw_payload.get("investigation_trace") or ["OpenClaw reasoned over the active PIRE case"]),
    }


def detect_protocol(text: str) -> tuple[str, str] | None:
    topics = detect_topics(text)
    if not topics:
        return None
    topic = topics[0]
    filt = topic_filter(topic)
    return (topic, filt) if filt else None


def run_terminal_command(pcap: str, command_text: str) -> dict[str, Any]:
    command_text = command_text.strip()
    if not command_text:
        raise ValueError("Missing command")
    args = shlex.split(command_text)
    if not args:
        raise ValueError("Missing command")
    if args[0] not in ALLOWED_TERMINAL_BINARIES:
        raise ValueError(f"Command not allowed: {args[0]}")

    resolved_pcap = str(resolve_pcap(pcap))
    normalized: list[str] = []
    for arg in args:
        if arg == "@current":
            normalized.append(resolved_pcap)
        else:
            normalized.append(arg)

    proc = run_command(normalized)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    combined = stdout if stdout else stderr
    if stdout and stderr:
        combined = f"{stdout}\n--- stderr ---\n{stderr}"
    return {
        "command": " ".join(normalized),
        "returncode": proc.returncode,
        "output": combined.strip(),
        "overview": build_overview(pcap),
    }
