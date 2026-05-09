from __future__ import annotations

import json
import logging
import os
import socket
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

logger = logging.getLogger("uvicorn.error")

SYSTEM_PROMPT = """You are OpenClaw operating in PIRE mode.

PIRE is not the reasoning agent. You are.
PIRE is the packet workbench and evidence surface.

Your job on each substantive PIRE turn:
- understand the user's investigative goal
- preserve the active PIRE workflow instead of drifting into generic chat
- treat the current PCAP as the primary evidence source
- keep three knowledge layers separate: current-case, experiential, protocol
- seek missing knowledge deliberately rather than pretending certainty
- prefer packet-grounded statements and explicit uncertainty
- propose targeted API/reference questions only when they reduce uncertainty
- never invent or auto-create hypotheses; only reflect a hypothesis if the user explicitly states one
- never generate detections unless explicitly requested
- use only the PIRE evidence bundle already provided in this turn
- if screenshot attachments are present, inspect them when the model can actually see them; if not, say that briefly and fall back to the packet/case evidence without bluffing
- do not call tools, run commands, inspect files, browse, or gather new evidence yourself

Mandatory workflow:
1. identify the current investigative question
2. inspect current-case evidence
3. inspect relevant protocol knowledge
4. inspect relevant experiential knowledge
5. keep the three layers separate
6. decide the best next move
7. answer usefully and concretely
8. update gaps / next steps / save pressure

Knowledge categories:
- protocol knowledge: durable protocol understanding, normal patterns, terminology, useful filters
- experiential knowledge: prior cases, heuristics, lessons, attack ideas, detections, confidence notes
- current-case knowledge: PCAP inventory, frame-grounded findings, candidate questions, next steps

If evidence is weak:
- say what is observed
- say what is inferred
- say what is still missing
- suggest the next narrowest useful move
- do not try to collect the missing evidence yourself; propose it as the next step instead

Return only JSON with this shape:
{
  "mode": "direct-question" | "investigation-loop" | "clarify",
  "reply": "string",
  "investigation_trace": ["short step", "short step"],
  "focus": "string or null",
  "summary": "short current-case summary",
  "observation": "short observed fact summary",
  "interpretation": "short interpretation or uncertainty summary",
  "next_step": "string",
  "gaps": ["string"],
  "save_pressure": ["string"],
  "promotion_candidates": ["string"],
  "api_questions": [
    {
      "question": "string",
      "why_ask": "string",
      "pcap_evidence": "string",
      "experiential_knowledge": "string",
      "protocol_knowledge": "string",
      "helpful_answer_would": "string"
    }
  ]
}

Rules for reply style:
- sound like a real OpenClaw investigator, not a UI widget
- keep the workflow visible
- put the bottom line first
- separate current-case, protocol, and experiential knowledge explicitly when they matter
- if you propose API questions, render them as a numbered list in the reply body and make clear the user can say "ask 1", "ask 1-3", or "1 then 5 then 2"
- if you answer directly, anchor the answer in the evidence you actually have and state uncertainty plainly
- avoid dumping process chatter into the main answer body; keep the answer readable
- return the JSON immediately without using any tools
"""


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def openclaw_config() -> dict[str, Any]:
    base_url = _env("PIRE_OPENCLAW_API_BASE") or _env("OPENCLAW_API_BASE")
    api_key = _env("PIRE_OPENCLAW_API_KEY") or _env("OPENCLAW_GATEWAY_TOKEN") or _env("OPENAI_API_KEY")
    model = _env("PIRE_OPENCLAW_MODEL", "openclaw/default")
    timeout = int(_env("PIRE_OPENCLAW_TIMEOUT_SECONDS", "120") or "120")
    missing: list[str] = []
    if not base_url:
        missing.append("PIRE_OPENCLAW_API_BASE")
    if not api_key:
        missing.append("PIRE_OPENCLAW_API_KEY")
    return {
        "enabled": not missing,
        "base_url": base_url.rstrip("/"),
        "model": model,
        "timeout_seconds": timeout,
        "missing": missing,
    }


def openclaw_status() -> dict[str, Any]:
    config = openclaw_config()
    return {
        "enabled": config["enabled"],
        "base_url": config["base_url"] or None,
        "model": config["model"],
        "missing": config["missing"],
    }


def require_openclaw() -> dict[str, Any]:
    config = openclaw_config()
    if config["enabled"]:
        return config
    missing = ", ".join(config["missing"])
    raise RuntimeError(
        "PIRE now depends on an OpenClaw chat backend for investigation turns. "
        f"Missing configuration: {missing}."
    )


def _normalize_json_text(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
    return text.strip()


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = _normalize_json_text(text)
    try:
        payload = json.loads(cleaned)
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        payload = json.loads(cleaned[start : end + 1])
        if isinstance(payload, dict):
            return payload
    raise ValueError("OpenClaw did not return a valid JSON object")


def _message_text(message: dict[str, Any]) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
        return "\n".join(part for part in parts if part)
    return str(content)


def _compact_case(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "pcap_path": case.get("pcap_path"),
        "status": case.get("status"),
        "current_focus": case.get("current_focus"),
        "summary": case.get("summary"),
        "questions": (case.get("questions") or [])[:5],
        "gaps": (case.get("gaps") or [])[:8],
        "next_steps": (case.get("next_steps") or [])[:8],
        "api_questions": (case.get("api_questions") or [])[:5],
        "recent_turns": (case.get("investigation_history") or [])[-4:],
    }


def _compact_knowledge(knowledge: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key in ("protocol", "experience", "current_case"):
        entries = knowledge.get(key) or []
        compact[key] = [
            {
                "title": entry.get("title"),
                "snippet": entry.get("snippet"),
                "source": entry.get("source"),
            }
            for entry in entries[:3]
        ]
    return compact


def _compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for topic, details in (evidence or {}).items():
        rows = (details or {}).get("rows") or []
        compact[topic] = {
            "summary": details.get("summary"),
            "frame_count": details.get("frame_count"),
            "rows": rows[:8],
            "zeek": (details or {}).get("zeek"),
        }
    return compact


def build_user_prompt(*, pcap: str, user_message: str, case: dict[str, Any], context: dict[str, Any], overview: dict[str, Any], attachments: list[dict[str, Any]] | None = None) -> str:
    compact_overview = {
        "pcap": overview.get("pcap"),
        "metadata": (overview.get("metadata") or {}).get("parsed", {}),
        "top_protocols": overview.get("top_protocols", [])[:10],
        "timeline_preview": overview.get("timeline_preview", [])[:8],
        "zeek_summary": overview.get("zeek_summary", {}),
    }
    payload = {
        "pcap": pcap,
        "user_message": user_message,
        "attachments": [
            {"name": item.get("name"), "mime_type": item.get("mime_type"), "kind": item.get("kind", "image")}
            for item in (attachments or [])
        ],
        "case_snapshot": _compact_case(case),
        "investigation_context": {
            "main_topic": context.get("main_topic"),
            "topics": context.get("topics", [])[:8],
            "broad_protocols": context.get("broad_protocols", [])[:12],
            "knowledge": _compact_knowledge(context.get("knowledge") or {}),
            "evidence": _compact_evidence(context.get("evidence") or {}),
            "current_state": context.get("current_state", {}),
            "selected_knowledge": context.get("selected_knowledge"),
        },
        "overview": compact_overview,
    }
    return (
        "Here is the active PIRE case context. Use it to continue the investigation workflow.\n\n"
        + json.dumps(payload, indent=2)
    )


def ask_openclaw(*, pcap: str, user_message: str, case: dict[str, Any], context: dict[str, Any], overview: dict[str, Any], attachments: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    config = require_openclaw()
    request_id = f"pire-{uuid.uuid4()}"
    prompt = build_user_prompt(pcap=pcap, user_message=user_message, case=case, context=context, overview=overview, attachments=attachments)
    user_content: str | list[dict[str, Any]] = prompt
    if attachments:
        user_content = [{"type": "text", "text": prompt}]
        for item in attachments:
            data_url = str(item.get("data_url") or "")
            mime_type = str(item.get("mime_type") or "")
            if data_url.startswith("data:image/") or mime_type.startswith("image/"):
                user_content.append({"type": "image_url", "image_url": {"url": data_url}})
    request_body = {
        "model": config["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.2,
    }
    backend_model = _env("PIRE_OPENCLAW_BACKEND_MODEL")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ.get('PIRE_OPENCLAW_API_KEY') or os.environ.get('OPENCLAW_GATEWAY_TOKEN') or os.environ.get('OPENAI_API_KEY')}",
        "x-openclaw-session-key": request_id,
    }
    if backend_model:
        headers["x-openclaw-model"] = backend_model
    data = json.dumps(request_body).encode("utf-8")
    request = urllib.request.Request(
        config["base_url"] + "/chat/completions",
        data=data,
        method="POST",
        headers=headers,
    )
    logger.info(
        "ask_openclaw start request_id=%s pcap=%s model=%s backend_model=%s timeout=%ss prompt_chars=%s topic=%s",
        request_id,
        pcap,
        config["model"],
        backend_model or "",
        config["timeout_seconds"],
        len(prompt),
        context.get("main_topic") or "",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=config["timeout_seconds"]) as response:
            body = response.read().decode("utf-8")
            raw = json.loads(body)
            logger.info(
                "ask_openclaw complete request_id=%s status=%s elapsed=%.3fs response_chars=%s",
                request_id,
                getattr(response, "status", "?"),
                time.perf_counter() - started,
                len(body),
            )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        logger.exception(
            "ask_openclaw http_error request_id=%s code=%s elapsed=%.3fs detail=%s",
            request_id,
            exc.code,
            time.perf_counter() - started,
            detail[:1200],
        )
        raise RuntimeError(f"OpenClaw backend returned HTTP {exc.code}: {detail}") from exc
    except (TimeoutError, socket.timeout) as exc:
        logger.exception(
            "ask_openclaw timeout request_id=%s elapsed=%.3fs",
            request_id,
            time.perf_counter() - started,
        )
        raise RuntimeError(f"OpenClaw backend timed out after {config['timeout_seconds']} seconds") from exc
    except urllib.error.URLError as exc:
        logger.exception(
            "ask_openclaw url_error request_id=%s elapsed=%.3fs",
            request_id,
            time.perf_counter() - started,
        )
        raise RuntimeError(f"Unable to reach OpenClaw backend: {exc}") from exc

    choices = raw.get("choices") or []
    if not choices:
        raise RuntimeError("OpenClaw backend returned no choices")
    message = choices[0].get("message") or {}
    text = _message_text(message)
    try:
        payload = _extract_json_object(text)
    except Exception:
        payload = {
            "mode": "direct-question",
            "reply": text.strip() or "OpenClaw returned an empty reply.",
            "investigation_trace": ["OpenClaw replied without structured JSON"],
            "focus": context.get("main_topic"),
            "summary": text.strip()[:400],
            "observation": None,
            "interpretation": "The backend returned plain text instead of the requested JSON contract.",
            "next_step": "Continue the investigation with a narrower follow-up if needed.",
            "gaps": [],
            "hypotheses": [],
            "save_pressure": [],
            "promotion_candidates": [],
            "api_questions": [],
        }
    payload.setdefault("mode", "direct-question")
    payload.setdefault("reply", text.strip() or "OpenClaw returned an empty reply.")
    payload.setdefault("investigation_trace", [])
    payload.setdefault("focus", context.get("main_topic"))
    payload.setdefault("summary", payload.get("reply", ""))
    payload.setdefault("observation", None)
    payload.setdefault("interpretation", None)
    payload.setdefault("next_step", None)
    payload.setdefault("gaps", [])
    payload.setdefault("hypotheses", [])
    payload.setdefault("save_pressure", [])
    payload.setdefault("promotion_candidates", [])
    payload.setdefault("api_questions", [])
    return payload
