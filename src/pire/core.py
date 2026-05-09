from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import math
import mimetypes
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import orjson

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("PIRE_DATA_DIR", str(BASE_DIR / "pire"))).resolve()
INCOMING_DIR = DATA_DIR / "incoming"
OUTPUT_DIR = DATA_DIR / "output"
EXPORTS_DIR = DATA_DIR / "exports"
CACHE_DIR = DATA_DIR / "cache"
ZEEK_CACHE_DIR = Path(os.environ.get("PIRE_ZEEK_CACHE_DIR", str(CACHE_DIR / "zeek"))).resolve()
ZEEK_LOG_DIR = Path(os.environ.get("PIRE_ZEEK_LOG_DIR", str(ZEEK_CACHE_DIR / "logs"))).resolve()
STATE_PATH = CACHE_DIR / "ui-state.json"

COMMON_TLDS = {"com", "net", "org", "edu", "gov", "mil", "int", "us", "uk", "ca", "de", "fr", "au", "jp", "kr", "cn"}
COMMON_USER_AGENT_HINTS = {"mozilla", "chrome", "safari", "firefox", "edge", "opera", "curl", "wget", "python-requests", "powershell"}
BORING_FILE_MIME_HINTS = {
    "text/html", "application/json", "application/xml", "text/javascript", "image/png", "image/jpeg",
    "image/gif", "image/x-icon", "font/woff", "font/woff2", "application/ocsp-response",
    "application/x-x509-ca-cert", "application/pkix-crl",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".docb", ".doc", ".dotm"}

DEFAULT_SUMMARY_LIMIT = 40
TSHARK_UNAVAILABLE_TEXT = "tshark is not available in this runtime yet, so packet previews are unavailable."
BINARY_FALLBACKS = {
    "zeek": ["/opt/zeek/bin/zeek", "/usr/bin/zeek"],
    "zeek-cut": ["/opt/zeek/bin/zeek-cut", "/usr/bin/zeek-cut"],
    "zkg": ["/opt/zeek/bin/zkg", "/usr/bin/zkg"],
}
ZEEK_DEFAULT_LOGS = ["conn.log", "dns.log", "http.log", "files.log", "notice.log", "weird.log"]


def _strip_zeek_value(value: str) -> str:
    if not value or value == "-":
        return ""
    return value


def _split_zeek_multi_value(value: str) -> list[str]:
    text = _strip_zeek_value(value)
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def resolve_binary(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for candidate in BINARY_FALLBACKS.get(name, []):
        if Path(candidate).exists():
            return candidate
    return None


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def zeek_available() -> bool:
    return resolve_binary("zeek") is not None and resolve_binary("zeek-cut") is not None


def read_summary_is_degraded(read_summary: dict[str, Any] | None) -> bool:
    if not isinstance(read_summary, dict):
        return True
    fallback_fields = [
        read_summary.get("endpoints_preview"),
        read_summary.get("conversations_preview"),
        read_summary.get("hosts_preview"),
    ]
    return any(value == TSHARK_UNAVAILABLE_TEXT for value in fallback_fields)


def safe_text_block(loader: Callable[[], str], fallback: str) -> str:
    try:
        return loader()
    except (FileNotFoundError, RuntimeError):
        return fallback


def safe_table_rows(loader: Callable[[], list[dict[str, str]]]) -> list[dict[str, str]]:
    try:
        return loader()
    except (FileNotFoundError, RuntimeError):
        return []


def safe_lines(loader: Callable[[], list[str]]) -> list[str]:
    try:
        return loader()
    except (FileNotFoundError, RuntimeError):
        return []


def ensure_dirs() -> None:
    for path in (INCOMING_DIR, OUTPUT_DIR, EXPORTS_DIR, CACHE_DIR, ZEEK_CACHE_DIR, ZEEK_LOG_DIR):
        path.mkdir(parents=True, exist_ok=True)
    try:
        from pire.runtime import ensure_runtime_structure

        ensure_runtime_structure()
    except Exception:
        pass


def run_command(
    command: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(command, capture_output=True, text=True, check=False, cwd=cwd, env=merged_env)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_bytes(orjson.dumps(data, option=orjson.OPT_INDENT_2))


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def resolve_pcap(path: str) -> Path:
    candidate = Path(path)
    if candidate.exists():
        return candidate.resolve()
    incoming_candidate = (INCOMING_DIR / path).resolve()
    if incoming_candidate.exists():
        return incoming_candidate
    raise FileNotFoundError(f"PCAP not found: {path}")


def pcap_relative_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(INCOMING_DIR.resolve()))
    except Exception:
        return path.name


def set_current_pcap(pcap: str) -> dict[str, Any]:
    ensure_dirs()
    pcap_path = resolve_pcap(pcap)
    state = {"current_pcap": pcap_relative_path(pcap_path)}
    write_json(STATE_PATH, state)
    return state


def current_pcap() -> str | None:
    ensure_dirs()
    state = read_json(STATE_PATH) or {}
    current = state.get("current_pcap")
    if current:
        try:
            resolve_pcap(current)
            return current
        except FileNotFoundError:
            return None
    pcaps = list_pcaps()
    return pcaps[0]["relative_path"] if pcaps else None


def parse_capinfos(raw: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower().replace(" ", "_")
        parsed[key] = value.strip()
    return parsed


def parse_tshark_table(raw: str) -> list[dict[str, str]]:
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return []
    header = [part.strip() for part in lines[0].split("\t")]
    rows: list[dict[str, str]] = []
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < len(header):
            parts += [""] * (len(header) - len(parts))
        row = {header[i]: parts[i].strip() for i in range(len(header))}
        rows.append(row)
    return rows


def is_public_ip(value: str) -> bool:
    try:
        return not ipaddress.ip_address(value).is_private
    except Exception:
        return False


def zeek_cache_slug(pcap: str) -> str:
    pcap_path = resolve_pcap(pcap)
    stat = pcap_path.stat()
    token = f"{pcap_relative_path(pcap_path)}::{stat.st_size}::{int(stat.st_mtime)}"
    return hashlib.sha1(token.encode("utf-8")).hexdigest()[:16]


def zeek_run_dir(pcap: str) -> Path:
    return ZEEK_LOG_DIR / zeek_cache_slug(pcap)


def parse_zeek_fields(path: Path) -> list[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if line.startswith("#fields\t"):
                return line.split("\t")[1:]
            if line and not line.startswith("#"):
                break
    return []


def parse_zeek_log(path: Path, limit: int | None = None) -> list[dict[str, str]]:
    if not path.exists():
        return []
    fields: list[str] = []
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields\t"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                rows.append({"_raw": line})
            else:
                parts = line.split("\t")
                if len(parts) < len(fields):
                    parts += [""] * (len(fields) - len(parts))
                parts = parts[: len(fields)]
                rows.append({fields[index]: parts[index] for index in range(len(fields))})
            if limit is not None and len(rows) >= limit:
                break
    return rows


def ensure_zeek_logs(pcap: str, *, force: bool = False) -> Path:
    ensure_dirs()
    if not zeek_available():
        raise RuntimeError("Zeek is not available in this runtime")
    pcap_path = resolve_pcap(pcap)
    run_dir = zeek_run_dir(pcap)
    run_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = run_dir / "_meta.json"
    current_meta = {
        "pcap": str(pcap_path),
        "relative_path": pcap_relative_path(pcap_path),
        "size": pcap_path.stat().st_size,
        "mtime": int(pcap_path.stat().st_mtime),
    }
    existing_meta = read_json(metadata_path) or {}
    conn_log = run_dir / "conn.log"
    if not force and conn_log.exists() and existing_meta == current_meta:
        return run_dir

    for old_log in run_dir.glob("*.log"):
        old_log.unlink()

    zeek_bin = resolve_binary("zeek")
    if not zeek_bin:
        raise RuntimeError("Unable to resolve Zeek binary")
    proc = run_command([zeek_bin, "-Cr", str(pcap_path), "local"], cwd=run_dir)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"zeek failed with {proc.returncode}")

    write_json(metadata_path, current_meta)
    return run_dir


def _query_alias_candidates(field: str) -> list[str]:
    normalized = field.strip()
    alias_map = {
        "src_ip": ["src_ip", "id.orig_h", "src"],
        "dest_ip": ["dest_ip", "id.resp_h", "dst"],
        "src_port": ["src_port", "id.orig_p"],
        "dest_port": ["dest_port", "id.resp_p"],
        "id.orig_h": ["src_ip", "id.orig_h", "src"],
        "id.resp_h": ["dest_ip", "id.resp_h", "dst"],
        "id.orig_p": ["src_port", "id.orig_p"],
        "id.resp_p": ["dest_port", "id.resp_p"],
    }
    return alias_map.get(normalized, [normalized])


def _row_values_for_query(row: dict[str, str], field: str) -> list[str]:
    values: list[str] = []
    for key in _query_alias_candidates(field):
        value = _strip_zeek_value(str(row.get(key, "")))
        if value:
            values.append(value)
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _query_value_matches(candidate: str, expected: str) -> bool:
    candidate_folded = candidate.casefold()
    expected_folded = expected.casefold()
    if "*" in expected_folded or "?" in expected_folded:
        return fnmatch.fnmatchcase(candidate_folded, expected_folded)
    return candidate_folded == expected_folded


class _LogQueryParser:
    def __init__(self, text: str):
        self.tokens = self._tokenize(text)
        self.index = 0

    @staticmethod
    def _tokenize(text: str) -> list[tuple[str, str]]:
        tokens: list[tuple[str, str]] = []
        i = 0
        while i < len(text):
            char = text[i]
            if char.isspace():
                i += 1
                continue
            if text.startswith("&&", i):
                tokens.append(("AND", "&&"))
                i += 2
                continue
            if text.startswith("||", i):
                tokens.append(("OR", "||"))
                i += 2
                continue
            if text.startswith("!=", i):
                tokens.append(("NE", "!="))
                i += 2
                continue
            if char == "=":
                tokens.append(("EQ", char))
                i += 1
                continue
            if char == "(":
                tokens.append(("LPAREN", char))
                i += 1
                continue
            if char == ")":
                tokens.append(("RPAREN", char))
                i += 1
                continue
            if char in {'"', "'"}:
                quote = char
                i += 1
                start = i
                while i < len(text) and text[i] != quote:
                    i += 1
                tokens.append(("WORD", text[start:i]))
                if i < len(text) and text[i] == quote:
                    i += 1
                continue
            start = i
            while i < len(text) and (not text[i].isspace()) and text[i] not in "()=&|!":
                i += 1
            word = text[start:i]
            upper = word.upper()
            if upper == "AND":
                tokens.append(("AND", word))
            elif upper == "OR":
                tokens.append(("OR", word))
            elif upper == "NOT":
                tokens.append(("NOT", word))
            else:
                tokens.append(("WORD", word))
        return tokens

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _consume(self, kind: str | None = None) -> tuple[str, str]:
        token = self._peek()
        if token is None:
            raise ValueError("Unexpected end of query")
        if kind and token[0] != kind:
            raise ValueError(f"Expected {kind}, got {token[0]}")
        self.index += 1
        return token

    def _starts_primary(self, token: tuple[str, str] | None) -> bool:
        return bool(token and token[0] in {"WORD", "LPAREN", "NOT"})

    def parse(self):
        predicate = self._parse_or()
        if self._peek() is not None:
            raise ValueError(f"Unexpected token: {self._peek()[1]}")
        return predicate

    def _parse_or(self):
        left = self._parse_and()
        while self._peek() and self._peek()[0] == "OR":
            self._consume("OR")
            right = self._parse_and()
            left = (lambda lhs=left, rhs=right: (lambda row: lhs(row) or rhs(row)))()
        return left

    def _parse_and(self):
        left = self._parse_not()
        while True:
            token = self._peek()
            if token and token[0] == "AND":
                self._consume("AND")
                right = self._parse_not()
                left = (lambda lhs=left, rhs=right: (lambda row: lhs(row) and rhs(row)))()
                continue
            if self._starts_primary(token):
                right = self._parse_not()
                left = (lambda lhs=left, rhs=right: (lambda row: lhs(row) and rhs(row)))()
                continue
            break
        return left

    def _parse_not(self):
        token = self._peek()
        if token and token[0] == "NOT":
            self._consume("NOT")
            inner = self._parse_not()
            return lambda row: not inner(row)
        return self._parse_primary()

    def _parse_primary(self):
        token = self._peek()
        if token is None:
            raise ValueError("Unexpected end of query")
        if token[0] == "LPAREN":
            self._consume("LPAREN")
            inner = self._parse_or()
            self._consume("RPAREN")
            return inner
        return self._parse_predicate()

    def _parse_predicate(self):
        token = self._consume("WORD")
        field_or_term = token[1]
        comparator = self._peek()
        if comparator and comparator[0] in {"EQ", "NE"}:
            self._consume(comparator[0])
            value = self._consume("WORD")[1]
            expected = value.casefold()
            if comparator[0] == "EQ":
                return lambda row, field=field_or_term, expected=expected: any(_query_value_matches(candidate, expected) for candidate in _row_values_for_query(row, field))
            return lambda row, field=field_or_term, expected=expected: bool(_row_values_for_query(row, field)) and all(not _query_value_matches(candidate, expected) for candidate in _row_values_for_query(row, field))
        needle = field_or_term.casefold()
        if "*" in needle or "?" in needle:
            return lambda row, needle=needle: any(fnmatch.fnmatchcase(str(value or "").casefold(), needle) for value in row.values())
        return lambda row, needle=needle: any(needle in str(value or "").casefold() for value in row.values())


def _compile_log_query(query: str):
    text = query.strip()
    if not text:
        return None
    return _LogQueryParser(text).parse()


def _with_log_aliases(row: dict[str, str]) -> dict[str, str]:
    enriched = dict(row)
    if "src_ip" not in enriched:
        enriched["src_ip"] = _strip_zeek_value(row.get("id.orig_h", "")) or _strip_zeek_value(row.get("src", ""))
    if "dest_ip" not in enriched:
        enriched["dest_ip"] = _strip_zeek_value(row.get("id.resp_h", "")) or _strip_zeek_value(row.get("dst", ""))
    if "src_port" not in enriched:
        enriched["src_port"] = _strip_zeek_value(row.get("id.orig_p", ""))
    if "dest_port" not in enriched:
        enriched["dest_port"] = _strip_zeek_value(row.get("id.resp_p", ""))
    return enriched


def _pcap_start_epoch(pcap: str) -> float | None:
    parsed = metadata_for_pcap(pcap).get("parsed", {})
    earliest = str(parsed.get("earliest_packet_time") or "").strip()
    if not earliest:
        return None
    try:
        return datetime.strptime(earliest, "%Y-%m-%d %H:%M:%S.%f").timestamp()
    except ValueError:
        try:
            return datetime.strptime(earliest, "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            return None


def _with_pcap_offset(row: dict[str, str], pcap_start_epoch: float | None) -> dict[str, str]:
    enriched = dict(row)
    ts_value = _safe_float(str(row.get("ts", "")))
    if pcap_start_epoch is None or ts_value is None:
        enriched.setdefault("pcap_offset_s", "")
        enriched.setdefault("pcap_offset_ms", "")
        return enriched
    offset_ms = max(0, int(round((ts_value - pcap_start_epoch) * 1000)))
    enriched["pcap_offset_ms"] = str(offset_ms)
    enriched["pcap_offset_s"] = f"{offset_ms / 1000:.3f}"
    return enriched


def zeek_log_rows(pcap: str, log_name: str, limit: int = 80, q: str = "") -> list[dict[str, str]]:
    run_dir = ensure_zeek_logs(pcap)
    pcap_start_epoch = _pcap_start_epoch(pcap)
    rows = [_with_pcap_offset(_with_log_aliases(row), pcap_start_epoch) for row in parse_zeek_log(run_dir / log_name)]
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def _http_fallback_item_to_log_row(item: dict[str, Any], gap: dict[str, Any] | None = None) -> dict[str, str]:
    gap = gap or {}
    return {
        "ts": str(item.get("ts") or ""),
        "uid": str(item.get("uid") or ""),
        "id.orig_h": str(item.get("src") or gap.get("src") or ""),
        "id.orig_p": str(item.get("src_port") or gap.get("src_port") or ""),
        "id.resp_h": str(item.get("dest") or gap.get("dest") or ""),
        "id.resp_p": str(item.get("dest_port") or gap.get("dest_port") or ""),
        "method": str(item.get("method") or ""),
        "host": str(item.get("host") or ""),
        "uri": str(item.get("uri") or ""),
        "user_agent": str(item.get("user_agent") or ""),
        "status_code": str(item.get("response_code") or ""),
        "resp_mime_types": str(item.get("content_type") or ""),
        "source": "packet-fallback",
        "stream": str(item.get("stream") or ",".join(item.get("streams") or [])),
        "frames": ",".join(item.get("frames") or []),
        "request_frame": str(item.get("request_frame") or ""),
        "response_frame": str(item.get("response_frame") or ""),
    }


def http_log_fallback_rows(pcap: str, q: str = "", limit: int = 20) -> list[dict[str, str]]:
    run_dir = ensure_zeek_logs(pcap)
    conn_rows = parse_zeek_log(run_dir / "conn.log")
    http_rows = parse_zeek_log(run_dir / "http.log")
    gaps = _http_coverage_gaps(conn_rows, http_rows, run_dir)
    gap_by_uid = {str(item.get("uid") or ""): item for item in gaps}
    recovered = _http_gap_packet_fallbacks(pcap, gaps, limit=limit)
    rows: list[dict[str, str]] = []
    for item in recovered:
        gap = gap_by_uid.get(str(item.get("uid") or ""), {})
        rows.append(_with_log_aliases(_http_fallback_item_to_log_row(item, gap)))
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def zeek_log_fields(pcap: str, log_name: str) -> list[str]:
    run_dir = ensure_zeek_logs(pcap)
    fields = parse_zeek_fields(run_dir / log_name)
    enriched = list(fields)
    for field in ("pcap_offset_s", "pcap_offset_ms"):
        if field not in enriched:
            enriched.append(field)
    if "id.orig_h" in fields and "src_ip" not in enriched:
        enriched.append("src_ip")
    if "id.resp_h" in fields and "dest_ip" not in enriched:
        enriched.append("dest_ip")
    if "id.orig_p" in fields and "src_port" not in enriched:
        enriched.append("src_port")
    if "id.resp_p" in fields and "dest_port" not in enriched:
        enriched.append("dest_port")
    synthetic_fields = {
        "http.log": ("source", "stream", "frames", "request_frame", "response_frame"),
        "dns.log": ("source", "frame", "answers"),
        "files.log": ("source", "frames", "request_frame", "response_frame", "uri", "host"),
        "ssl.log": ("source", "frame", "handshake_type", "server_name", "cipher", "version"),
        "smtp.log": ("source", "frame"),
        "smb_files.log": ("source", "frame"),
        "smb_mapping.log": ("source", "frame"),
        "dce_rpc.log": ("source", "frame", "packet_type", "request_in", "response_in", "status"),
        "ldap.log": ("source", "frame", "object", "attribute"),
        "kerberos.log": ("source", "frame", "realm", "etype", "error_code", "padata_type", "response_to", "response_in"),
    }
    for field in synthetic_fields.get(log_name, ()):
        if field not in enriched:
            enriched.append(field)
    return enriched


def _first_nonempty(*values: str) -> str:
    for value in values:
        text = _strip_zeek_value(value)
        if text:
            return text
    return ""


def _uri_tail(value: str) -> str:
    text = _strip_zeek_value(value)
    if not text:
        return ""
    text = text.split("?", 1)[0].rstrip("/")
    return text.rsplit("/", 1)[-1] if text else ""


def _guess_mime_type(filename: str, content_type: str = "") -> str:
    explicit = _strip_zeek_value(content_type)
    if explicit:
        return explicit
    guess, _ = mimetypes.guess_type(_strip_zeek_value(filename))
    return guess or ""


def _tls_handshake_name(value: str) -> str:
    raw = _strip_zeek_value(value)
    mapping = {
        "1": "client_hello",
        "2": "server_hello",
        "11": "certificate",
        "12": "server_key_exchange",
        "14": "server_hello_done",
        "16": "client_key_exchange",
        "20": "finished",
    }
    return mapping.get(raw, raw)


def _ldap_protocol_op_name(value: str) -> str:
    raw = _strip_zeek_value(value)
    mapping = {
        "0": "bind_request",
        "1": "bind_response",
        "2": "unbind_request",
        "3": "search_request",
        "4": "search_result_entry",
        "5": "search_result_done",
        "6": "modify_request",
        "7": "modify_response",
        "8": "add_request",
        "9": "add_response",
        "10": "del_request",
        "11": "del_response",
        "12": "modify_dn_request",
        "13": "modify_dn_response",
        "14": "compare_request",
        "15": "compare_response",
        "16": "abandon_request",
        "23": "extended_request",
        "24": "extended_response",
    }
    return mapping.get(raw, raw)


def _ldap_result_name(value: str) -> str:
    raw = _strip_zeek_value(value)
    mapping = {
        "0": "success",
        "1": "operations_error",
        "2": "protocol_error",
        "3": "time_limit_exceeded",
        "4": "size_limit_exceeded",
        "32": "no_such_object",
        "49": "invalid_credentials",
        "50": "insufficient_access",
        "52": "unavailable",
    }
    return mapping.get(raw, raw)


def _dcerpc_pkt_type_name(value: str) -> str:
    raw = _strip_zeek_value(value)
    mapping = {
        "0": "request",
        "2": "response",
        "3": "fault",
        "11": "bind",
        "12": "bind_ack",
    }
    return mapping.get(raw, raw)


def _kerberos_msg_type_name(value: str) -> str:
    raw = _strip_zeek_value(value)
    mapping = {
        "10": "AS-REQ",
        "11": "AS-REP",
        "12": "TGS-REQ",
        "13": "TGS-REP",
        "14": "AP-REQ",
        "15": "AP-REP",
        "30": "KRB-ERROR",
    }
    return mapping.get(raw, raw)


def dns_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    proc = run_command([
        "tshark", "-r", str(pcap_path), "-Y", "dns",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "udp.srcport",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "udp.dstport",
        "-e", "tcp.dstport",
        "-e", "dns.qry.name",
        "-e", "dns.qry.type",
        "-e", "dns.flags.rcode",
        "-e", "dns.a",
        "-e", "dns.aaaa",
        "-e", "dns.cname",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    rows: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (14 - len(parts))
        ts, frame, src, udp_sport, tcp_sport, dest, udp_dport, tcp_dport, query, qtype, rcode, ans_a, ans_aaaa, ans_cname = parts[:14]
        answers = ",".join(value for value in [_strip_zeek_value(ans_a), _strip_zeek_value(ans_aaaa), _strip_zeek_value(ans_cname)] if value)
        row = _with_log_aliases({
            "ts": _strip_zeek_value(ts),
            "uid": "",
            "id.orig_h": _strip_zeek_value(src),
            "id.orig_p": _first_nonempty(udp_sport, tcp_sport),
            "id.resp_h": _strip_zeek_value(dest),
            "id.resp_p": _first_nonempty(udp_dport, tcp_dport),
            "query": _strip_zeek_value(query),
            "qtype_name": _strip_zeek_value(qtype),
            "rcode_name": _strip_zeek_value(rcode),
            "answers": answers,
            "source": "packet-fallback",
            "frame": _strip_zeek_value(frame),
        })
        rows.append(row)
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def files_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    run_dir = ensure_zeek_logs(pcap)
    conn_rows = parse_zeek_log(run_dir / "conn.log")
    http_rows = parse_zeek_log(run_dir / "http.log")
    rows: list[dict[str, str]] = []
    for item in _http_gap_packet_fallbacks(pcap, _http_coverage_gaps(conn_rows, http_rows, run_dir), limit=limit):
        uri = _strip_zeek_value(str(item.get("uri") or ""))
        filename = _uri_tail(uri)
        host = _strip_zeek_value(str(item.get("host") or ""))
        display_name = filename or (host + uri if uri else host)
        mime_type = _guess_mime_type(display_name, str(item.get("content_type") or ""))
        if not (uri or mime_type or display_name):
            continue
        row = _with_log_aliases({
            "ts": str(item.get("ts") or ""),
            "fuid": "",
            "uid": str(item.get("uid") or ""),
            "id.orig_h": str(item.get("src") or ""),
            "id.orig_p": str(item.get("src_port") or ""),
            "id.resp_h": str(item.get("dest") or ""),
            "id.resp_p": str(item.get("dest_port") or ""),
            "source": "http-packet-fallback",
            "mime_type": mime_type,
            "filename": display_name,
            "seen_bytes": "",
            "total_bytes": "",
            "sha256": "",
            "host": host,
            "uri": uri,
            "frames": ",".join(item.get("frames") or []),
            "request_frame": str(item.get("request_frame") or ""),
            "response_frame": str(item.get("response_frame") or ""),
        })
        rows.append(row)
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def ssl_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    proc = run_command([
        "tshark", "-r", str(pcap_path), "-Y", "tls.handshake",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.version",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    rows: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (10 - len(parts))
        ts, frame, src, sport, dest, dport, handshake_type, server_name, cipher, version = parts[:10]
        row = _with_log_aliases({
            "ts": _strip_zeek_value(ts),
            "uid": "",
            "id.orig_h": _strip_zeek_value(src),
            "id.orig_p": _strip_zeek_value(sport),
            "id.resp_h": _strip_zeek_value(dest),
            "id.resp_p": _strip_zeek_value(dport),
            "server_name": _strip_zeek_value(server_name),
            "cipher": _strip_zeek_value(cipher),
            "version": _strip_zeek_value(version),
            "source": "packet-fallback",
            "frame": _strip_zeek_value(frame),
            "handshake_type": _tls_handshake_name(handshake_type),
        })
        rows.append(row)
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def smtp_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    proc = run_command([
        "tshark", "-r", str(pcap_path), "-Y", "smtp",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "smtp.req.command",
        "-e", "smtp.req.parameter",
        "-e", "smtp.response.code",
        "-e", "smtp.response.parameter",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    rows: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (10 - len(parts))
        ts, frame, src, sport, dest, dport, command, parameter, rsp_code, rsp_param = parts[:10]
        row = _with_log_aliases({
            "ts": _strip_zeek_value(ts),
            "uid": "",
            "id.orig_h": _strip_zeek_value(src),
            "id.orig_p": _strip_zeek_value(sport),
            "id.resp_h": _strip_zeek_value(dest),
            "id.resp_p": _strip_zeek_value(dport),
            "helo": _strip_zeek_value(parameter) if _strip_zeek_value(command).upper() in {"HELO", "EHLO"} else "",
            "mailfrom": _strip_zeek_value(parameter) if _strip_zeek_value(command).upper() == "MAIL" else "",
            "rcptto": _strip_zeek_value(parameter) if _strip_zeek_value(command).upper() == "RCPT" else "",
            "last_reply": (" ".join(value for value in [_strip_zeek_value(rsp_code), _strip_zeek_value(rsp_param)] if value)).strip(),
            "source": "packet-fallback",
            "frame": _strip_zeek_value(frame),
        })
        rows.append(row)
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def smb_files_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    proc = run_command([
        "tshark", "-r", str(pcap_path), "-Y", "smb || smb2",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "smb.file",
        "-e", "smb.path",
        "-e", "smb.file_size",
        "-e", "smb2.filename",
        "-e", "smb2.tree",
        "-e", "smb2.create.disposition",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    rows=[]
    for line in proc.stdout.splitlines():
        parts=line.split("\t")
        parts += [""] * (12 - len(parts))
        ts, frame, src, sport, dest, dport, smb_file, smb_path, smb_size, smb2_filename, smb2_tree, smb2_disp = parts[:12]
        name = _first_nonempty(smb2_filename, smb_file)
        path = _first_nonempty(smb2_tree, smb_path)
        if not (name or path):
            continue
        rows.append(_with_log_aliases({
            "ts": _strip_zeek_value(ts),
            "id.orig_h": _strip_zeek_value(src),
            "id.orig_p": _strip_zeek_value(sport),
            "id.resp_h": _strip_zeek_value(dest),
            "id.resp_p": _strip_zeek_value(dport),
            "action": _first_nonempty(smb2_disp, "packet-fallback"),
            "path": path,
            "name": name,
            "size": _strip_zeek_value(smb_size),
            "source": "packet-fallback",
            "frame": _strip_zeek_value(frame),
        }))
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def smb_mapping_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    proc = run_command([
        "tshark", "-r", str(pcap_path), "-Y", "smb2.tree || smb.path",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "smb.path",
        "-e", "smb2.tree",
        "-e", "smb2.share_type",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    rows=[]
    for line in proc.stdout.splitlines():
        parts=line.split("\t")
        parts += [""] * (9 - len(parts))
        ts, frame, src, sport, dest, dport, smb_path, smb2_tree, share_type = parts[:9]
        path = _first_nonempty(smb2_tree, smb_path)
        if not path:
            continue
        rows.append(_with_log_aliases({
            "ts": _strip_zeek_value(ts),
            "id.orig_h": _strip_zeek_value(src),
            "id.orig_p": _strip_zeek_value(sport),
            "id.resp_h": _strip_zeek_value(dest),
            "id.resp_p": _strip_zeek_value(dport),
            "path": path,
            "share_type": _strip_zeek_value(share_type),
            "service": "smb",
            "source": "packet-fallback",
            "frame": _strip_zeek_value(frame),
        }))
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def dce_rpc_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    proc = run_command([
        "tshark", "-r", str(pcap_path), "-Y", "dcerpc",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "dcerpc.cn_bind_to_uuid",
        "-e", "dcerpc.opnum",
        "-e", "dcerpc.cn_sec_addr",
        "-e", "dcerpc.cn_call_id",
        "-e", "dcerpc.pkt_type",
        "-e", "dcerpc.request_in",
        "-e", "dcerpc.response_in",
        "-e", "dcerpc.cn_status",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    rows=[]
    for line in proc.stdout.splitlines():
        parts=line.split("\t")
        parts += [""] * (14 - len(parts))
        ts, frame, src, sport, dest, dport, endpoint, opnum, named_pipe, call_id, pkt_type, request_in, response_in, status = parts[:14]
        if not any((_strip_zeek_value(endpoint), _strip_zeek_value(opnum), _strip_zeek_value(named_pipe), _strip_zeek_value(call_id))):
            continue
        operation = _strip_zeek_value(opnum)
        pkt_type_name = _dcerpc_pkt_type_name(pkt_type)
        if pkt_type_name and operation:
            operation = f"{pkt_type_name}:{operation}"
        rows.append(_with_log_aliases({
            "ts": _strip_zeek_value(ts),
            "id.orig_h": _strip_zeek_value(src),
            "id.orig_p": _strip_zeek_value(sport),
            "id.resp_h": _strip_zeek_value(dest),
            "id.resp_p": _strip_zeek_value(dport),
            "endpoint": _strip_zeek_value(endpoint),
            "operation": operation or pkt_type_name,
            "named_pipe": _strip_zeek_value(named_pipe),
            "rtt": "",
            "uid": _strip_zeek_value(call_id),
            "source": "packet-fallback",
            "frame": _strip_zeek_value(frame),
            "packet_type": pkt_type_name,
            "request_in": _strip_zeek_value(request_in),
            "response_in": _strip_zeek_value(response_in),
            "status": _strip_zeek_value(status),
        }))
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def ldap_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    proc = run_command([
        "tshark", "-r", str(pcap_path), "-Y", "ldap",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "ldap.messageID",
        "-e", "ldap.protocolOp",
        "-e", "ldap.baseObject",
        "-e", "ldap.resultCode",
        "-e", "ldap.attributeDesc",
        "-e", "ldap.attributeType",
        "-e", "ldap.version",
        "-e", "ldap.name",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    rows=[]
    for line in proc.stdout.splitlines():
        parts=line.split("\t")
        parts += [""] * (15 - len(parts))
        ts, frame, src, sport, dest, dport, message_id, protocol_op, base_object, result_code, attr_desc, attr_type, version, bind_name = parts[:14]
        if not any((_strip_zeek_value(message_id), _strip_zeek_value(protocol_op), _strip_zeek_value(base_object), _strip_zeek_value(attr_desc), _strip_zeek_value(bind_name))):
            continue
        rows.append(_with_log_aliases({
            "ts": _strip_zeek_value(ts),
            "id.orig_h": _strip_zeek_value(src),
            "id.orig_p": _strip_zeek_value(sport),
            "id.resp_h": _strip_zeek_value(dest),
            "id.resp_p": _strip_zeek_value(dport),
            "message_id": _strip_zeek_value(message_id),
            "version": _strip_zeek_value(version),
            "opcode": _ldap_protocol_op_name(protocol_op),
            "result": _ldap_result_name(result_code),
            "object": _first_nonempty(base_object, bind_name),
            "attribute": _first_nonempty(attr_desc, attr_type),
            "source": "packet-fallback",
            "frame": _strip_zeek_value(frame),
        }))
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def kerberos_log_fallback_rows(pcap: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    proc = run_command([
        "tshark", "-r", str(pcap_path), "-Y", "kerberos",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "udp.srcport",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "udp.dstport",
        "-e", "tcp.dstport",
        "-e", "kerberos.msg_type",
        "-e", "kerberos.cname_string",
        "-e", "kerberos.sname_string",
        "-e", "kerberos.realm",
        "-e", "kerberos.etype",
        "-e", "kerberos.error_code",
        "-e", "kerberos.padata_type",
        "-e", "kerberos.response_to",
        "-e", "kerberos.response_in",
    ])
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    rows=[]
    for line in proc.stdout.splitlines():
        parts=line.split("\t")
        parts += [""] * (18 - len(parts))
        ts, frame, udp_src, udp_sport, tcp_sport, udp_dest, udp_dport, tcp_dport, msg_type, client, service, realm, etype, error_code, padata_type, response_to, response_in = parts[:17]
        if not any((_strip_zeek_value(msg_type), _strip_zeek_value(client), _strip_zeek_value(service), _strip_zeek_value(realm), _strip_zeek_value(error_code))):
            continue
        success = "success"
        if _strip_zeek_value(error_code):
            success = f"error:{_strip_zeek_value(error_code)}"
        elif _kerberos_msg_type_name(msg_type) == "KRB-ERROR":
            success = "error"
        rows.append(_with_log_aliases({
            "ts": _strip_zeek_value(ts),
            "id.orig_h": _strip_zeek_value(udp_src),
            "id.orig_p": _first_nonempty(udp_sport, tcp_sport),
            "id.resp_h": _strip_zeek_value(udp_dest),
            "id.resp_p": _first_nonempty(udp_dport, tcp_dport),
            "request_type": _kerberos_msg_type_name(msg_type),
            "service": _strip_zeek_value(service),
            "client": _strip_zeek_value(client),
            "success": success,
            "realm": _strip_zeek_value(realm),
            "etype": _strip_zeek_value(etype),
            "source": "packet-fallback",
            "frame": _strip_zeek_value(frame),
            "error_code": _strip_zeek_value(error_code),
            "padata_type": _strip_zeek_value(padata_type),
            "response_to": _strip_zeek_value(response_to),
            "response_in": _strip_zeek_value(response_in),
        }))
    if q:
        predicate = _compile_log_query(q)
        rows = [row for row in rows if predicate(row)]
    return rows[:limit] if limit and limit > 0 else rows


def zeek_log_fallback_rows(pcap: str, log_name: str, q: str = "", limit: int = 80) -> list[dict[str, str]]:
    if log_name == "http.log":
        rows = http_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "dns.log":
        rows = dns_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "files.log":
        rows = files_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "ssl.log":
        rows = ssl_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "smtp.log":
        rows = smtp_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "smb_files.log":
        rows = smb_files_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "smb_mapping.log":
        rows = smb_mapping_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "dce_rpc.log":
        rows = dce_rpc_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "ldap.log":
        rows = ldap_log_fallback_rows(pcap, q=q, limit=limit)
    elif log_name == "kerberos.log":
        rows = kerberos_log_fallback_rows(pcap, q=q, limit=limit)
    else:
        rows = []
    pcap_start_epoch = _pcap_start_epoch(pcap)
    return [_with_pcap_offset(row, pcap_start_epoch) for row in rows]


def _merge_zeek_and_fallback_rows(zeek_rows: list[dict[str, str]], fallback_rows: list[dict[str, str]], limit: int = 80) -> list[dict[str, str]]:
    merged: list[dict[str, str]] = []
    seen: set[tuple[str, ...]] = set()
    for row in zeek_rows + fallback_rows:
        key = (
            _strip_zeek_value(row.get("uid", "")),
            _strip_zeek_value(row.get("fuid", "")),
            _strip_zeek_value(row.get("ts", "")),
            _strip_zeek_value(row.get("id.orig_h", "")),
            _strip_zeek_value(row.get("id.orig_p", "")),
            _strip_zeek_value(row.get("id.resp_h", "")),
            _strip_zeek_value(row.get("id.resp_p", "")),
            _strip_zeek_value(row.get("query", "")),
            _strip_zeek_value(row.get("host", "")),
            _strip_zeek_value(row.get("uri", "")),
            _strip_zeek_value(row.get("filename", "")),
            _strip_zeek_value(row.get("server_name", "")),
            _strip_zeek_value(row.get("frame", row.get("request_frame", ""))),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(row)
        if limit and len(merged) >= limit:
            break
    return merged


def _conn_service(row: dict[str, str]) -> str:
    service = _strip_zeek_value(row.get("service", ""))
    if service:
        return service
    proto = row.get("proto", "")
    return proto or "unknown"


def _top_counts(values: list[str], *, key_name: str, limit: int = 8) -> list[dict[str, Any]]:
    counts = Counter(value for value in values if value)
    return [{key_name: name, "count": count} for name, count in counts.most_common(limit)]


def _add_pivots(section: dict[str, Any], *pivots: dict[str, str]) -> dict[str, Any]:
    section["pivots"] = [pivot for pivot in pivots if pivot]
    return section


def _http_status_is_error(value: str) -> bool:
    raw = _strip_zeek_value(value)
    if not raw:
        return False
    try:
        return int(raw) >= 400
    except ValueError:
        return False


def _dns_failure_rows(rows: list[dict[str, str]], limit: int = 10) -> list[dict[str, str]]:
    failures = [
        {
            "query": row.get("query", ""),
            "qtype_name": row.get("qtype_name", ""),
            "rcode_name": row.get("rcode_name", ""),
            "answers": row.get("answers", ""),
        }
        for row in rows
        if _strip_zeek_value(row.get("rcode_name", "")) not in {"", "NOERROR"}
    ]
    return failures[:limit]


def _http_error_rows(rows: list[dict[str, str]], limit: int = 10) -> list[dict[str, str]]:
    interesting = [
        {
            "host": row.get("host", ""),
            "uri": row.get("uri", ""),
            "method": row.get("method", ""),
            "status_code": row.get("status_code", ""),
            "user_agent": row.get("user_agent", ""),
        }
        for row in rows
        if _http_status_is_error(row.get("status_code", ""))
    ]
    return interesting[:limit]


def _safe_float(value: str | None) -> float | None:
    try:
        if value in {None, "", "-"}:
            return None
        return float(str(value))
    except Exception:
        return None


def _format_epoch_window(start: float | None, end: float | None = None) -> str:
    if start is None:
        return "unknown"
    start_struct = time.gmtime(start)
    if end is None:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", start_struct)
    end_struct = time.gmtime(end)
    if time.strftime("%Y-%m-%d %H:%M", start_struct) == time.strftime("%Y-%m-%d %H:%M", end_struct):
        return f"{time.strftime('%Y-%m-%d %H:%M:%S', start_struct)}–{time.strftime('%H:%M:%S UTC', end_struct)}"
    return f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', start_struct)} → {time.strftime('%Y-%m-%d %H:%M:%S UTC', end_struct)}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_unusual_user_agent(value: str) -> bool:
    lowered = _strip_zeek_value(value).lower()
    if not lowered:
        return False
    return not any(hint in lowered for hint in COMMON_USER_AGENT_HINTS)


def _is_likely_noise_notice(row: dict[str, str]) -> bool:
    text = " ".join(
        _strip_zeek_value(row.get(field, "")).lower()
        for field in ("note", "msg", "sub")
    )
    return any(token in text for token in ("certificate", "self signed", "x509", "ssl::invalid"))


def _is_likely_noise_weird(row: dict[str, str]) -> bool:
    text = " ".join(
        _strip_zeek_value(row.get(field, "")).lower()
        for field in ("name", "addl")
    )
    return any(token in text for token in ("line_terminated", "line terminator", "bad http line"))


def _attention_item(
    *,
    title: str,
    detail: str,
    score: int,
    tab: str,
    pivot_label: str,
    bucket: str,
    timestamp: float | None = None,
    focus: str = "",
    log_name: str = "",
    why: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "detail": detail,
        "score": score,
        "status": status or ("high" if score >= 7 else "medium" if score >= 4 else "low"),
        "pivot_tab": tab,
        "pivot_label": pivot_label,
        "bucket": bucket,
        "timestamp": timestamp,
        "focus": focus,
        "log_name": log_name,
        "why": why or detail,
    }


def _interesting_dns_items(rows: list[dict[str, str]], limit: int = 8) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in rows:
        query = _strip_zeek_value(row.get("query", ""))
        rcode = _strip_zeek_value(row.get("rcode_name", ""))
        qtype = _strip_zeek_value(row.get("qtype_name", ""))
        score = 0
        reasons: list[str] = []
        if rcode and rcode != "NOERROR":
            score += 4
            reasons.append(f"rcode {rcode}")
        if qtype == "TXT":
            score += 2
            reasons.append("TXT lookup")
        if len(query) > 40:
            score += 2
            reasons.append("long query")
        entropy = _entropy(query)
        if entropy > 4.0:
            score += 2
            reasons.append(f"entropy {entropy:.1f}")
        tld = query.rsplit(".", 1)[-1].lower() if "." in query else ""
        if tld and tld not in COMMON_TLDS:
            score += 1
            reasons.append(f"rare TLD .{tld}")
        if score <= 0 or not query:
            continue
        items.append(
            _attention_item(
                title=f"DNS anomaly: {query}",
                detail=", ".join(reasons),
                score=score,
                tab="zeek-dns",
                pivot_label="Open dns.log",
                bucket="Interesting DNS",
                timestamp=_safe_float(row.get("ts")),
                focus=query,
                log_name="dns.log",
                why="DNS queries with failures, TXT usage, or high-entropy names are often better first pivots than top talkers.",
            )
        )
    items.sort(key=lambda item: (-item["score"], item.get("timestamp") or 0.0))
    return items[:limit]


def _interesting_http_items(rows: list[dict[str, str]], limit: int = 8) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in rows:
        host = _strip_zeek_value(row.get("host", "")) or "(no host)"
        uri = _strip_zeek_value(row.get("uri", ""))
        status_code = _strip_zeek_value(row.get("status_code", ""))
        user_agent = _strip_zeek_value(row.get("user_agent", ""))
        source = _strip_zeek_value(row.get("source", ""))
        score = 0
        reasons: list[str] = []
        if _http_status_is_error(status_code):
            score += 3
            reasons.append(f"HTTP {status_code}")
        if _is_unusual_user_agent(user_agent):
            score += 2
            reasons.append(f"unusual user agent {user_agent}")
        method = _strip_zeek_value(row.get("method", ""))
        if method in {"PUT", "DELETE", "CONNECT"}:
            score += 1
            reasons.append(f"method {method}")
        if source == "packet-fallback":
            score += 1
            reasons.append("recovered from packets because Zeek missed the HTTP row")
            if method == "POST":
                score += 1
                reasons.append("method POST")
            if uri and uri not in {"/", "/index.html"}:
                score += 1
                reasons.append(f"uri {uri}")
            resp_host = _strip_zeek_value(row.get("id.resp_h", ""))
            resp_port = _strip_zeek_value(row.get("id.resp_p", ""))
            direct_ip_host = resp_host + ((":" + resp_port) if resp_port else "")
            if host and host == direct_ip_host:
                score += 1
                reasons.append("direct-to-IP HTTP host")
        if score <= 0:
            continue
        focus = f"{host}{uri}" if uri else host
        items.append(
            _attention_item(
                title=f"HTTP signal: {host}",
                detail=", ".join(reasons) + (f" • {uri}" if uri else ""),
                score=score,
                tab="zeek-http",
                pivot_label="Open http.log",
                bucket="Interesting HTTP",
                timestamp=_safe_float(row.get("ts")),
                focus=focus,
                log_name="http.log",
                why="HTTP errors, odd user agents, and packet-recovered HTTP gaps can all be meaningful application-layer pivots.",
            )
        )
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in sorted(items, key=lambda item: (-item["score"], item.get("timestamp") or 0.0)):
        key = (str(item.get("title") or ""), str(item.get("detail") or ""), str(item.get("focus") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= limit:
            break
    return deduped


def _interesting_file_items(rows: list[dict[str, str]], limit: int = 8) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in rows:
        filename = _strip_zeek_value(row.get("filename", ""))
        mime_type = _strip_zeek_value(row.get("mime_type", ""))
        seen_bytes = _strip_zeek_value(row.get("seen_bytes", ""))
        score = 0
        reasons: list[str] = []
        extension = Path(filename).suffix.lower() if filename else ""
        if mime_type and mime_type not in BORING_FILE_MIME_HINTS:
            score += 3
            reasons.append(f"mime {mime_type}")
        if extension in MACRO_EXTENSIONS:
            score += 3
            reasons.append(f"macro-capable extension {extension}")
        if filename and not extension:
            score += 1
            reasons.append("filename lacks extension")
        if score <= 0:
            continue
        items.append(
            _attention_item(
                title=f"File transfer: {filename or mime_type or 'interesting file'}",
                detail=", ".join(reasons) + (f" • seen_bytes {seen_bytes}" if seen_bytes else ""),
                score=score,
                tab="zeek-files",
                pivot_label="Open files.log",
                bucket="Interesting Files",
                timestamp=_safe_float(row.get("ts")),
                focus=filename or mime_type,
                log_name="files.log",
                why="Suspicious file types and macro-capable documents are straight out of the file-transfer triage style from your repo.",
            )
        )
    items.sort(key=lambda item: (-item["score"], item.get("timestamp") or 0.0))
    return items[:limit]


def _interesting_tls_items(ssl_rows: list[dict[str, str]], x509_rows: list[dict[str, str]], limit: int = 8) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    noise_notes: list[str] = []
    for row in ssl_rows:
        validation_status = _strip_zeek_value(row.get("validation_status", ""))
        server_name = _strip_zeek_value(row.get("server_name", "")) or _strip_zeek_value(row.get("id.resp_h", ""))
        if not validation_status or validation_status == "ok":
            continue
        if any(token in validation_status.lower() for token in ("certificate", "self signed", "unable to get local issuer")):
            noise_notes.append(f"TLS validation noise present for {server_name}: {validation_status}")
            continue
        items.append(
            _attention_item(
                title=f"TLS validation signal: {server_name or 'endpoint'}",
                detail=f"validation_status={validation_status}",
                score=4,
                tab="zeek-ssl",
                pivot_label="Open ssl.log",
                bucket="TLS / Certificate Signals",
                timestamp=_safe_float(row.get("ts")),
                focus=server_name,
                log_name="ssl.log",
                why="Non-routine TLS validation problems can matter, but routine exercise cert noise is deliberately down-ranked here.",
            )
        )
    for row in x509_rows:
        subject = _strip_zeek_value(row.get("certificate.subject", ""))
        issuer = _strip_zeek_value(row.get("certificate.issuer", ""))
        if not subject or not issuer or subject != issuer:
            continue
        noise_notes.append(f"Self-issued certificate observed: {subject}")
    items.sort(key=lambda item: (-item["score"], item.get("timestamp") or 0.0))
    return items[:limit], noise_notes[:4]


def _interesting_notice_weird_items(notice_rows: list[dict[str, str]], weird_rows: list[dict[str, str]], limit: int = 8) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    downranked: list[str] = []
    for row in notice_rows:
        text = " | ".join(_strip_zeek_value(row.get(field, "")) for field in ("note", "msg", "sub") if _strip_zeek_value(row.get(field, "")))
        if not text:
            continue
        if _is_likely_noise_notice(row):
            downranked.append(f"Notice down-ranked as likely exercise noise: {text}")
            continue
        items.append(
            _attention_item(
                title=f"Notice: {_strip_zeek_value(row.get('note', 'event')) or 'event'}",
                detail=text,
                score=5,
                tab="zeek-notice",
                pivot_label="Open notice.log",
                bucket="Notice / Weird Signals",
                timestamp=_safe_float(row.get("ts")),
                focus=_strip_zeek_value(row.get("src", "")) or _strip_zeek_value(row.get("dst", "")),
                log_name="notice.log",
                why="Notices are useful when they are specific, but the routine cert-noise class is intentionally kept out of the main attention list.",
            )
        )
    for row in weird_rows:
        name = _strip_zeek_value(row.get("name", ""))
        addl = _strip_zeek_value(row.get("addl", ""))
        if not name and not addl:
            continue
        if _is_likely_noise_weird(row):
            downranked.append(f"Weird down-ranked as likely exercise noise: {name or addl}")
            continue
        items.append(
            _attention_item(
                title=f"Weird: {name or 'oddity'}",
                detail=addl or name,
                score=3,
                tab="zeek-weird",
                pivot_label="Open weird.log",
                bucket="Notice / Weird Signals",
                timestamp=_safe_float(row.get("ts")),
                focus=_strip_zeek_value(row.get("id.orig_h", "")) or _strip_zeek_value(row.get("id.resp_h", "")),
                log_name="weird.log",
                why="Unusual parser/protocol oddities can matter, but the common line-termination class is deliberately down-ranked.",
            )
        )
    items.sort(key=lambda item: (-item["score"], item.get("timestamp") or 0.0))
    return items[:limit], downranked[:6]


def _interesting_smb_rpc_items(smb_files_rows: list[dict[str, str]], smb_mapping_rows: list[dict[str, str]], dce_rpc_rows: list[dict[str, str]], limit: int = 8) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in smb_files_rows[: max(limit * 2, 12)]:
        action = _strip_zeek_value(row.get("action", ""))
        path = _strip_zeek_value(row.get("path", ""))
        name = _strip_zeek_value(row.get("name", ""))
        if not any(value for value in (action, path, name)):
            continue
        items.append(
            _attention_item(
                title=f"SMB file activity: {action or 'file event'}",
                detail=" • ".join(value for value in (path, name) if value),
                score=4,
                tab="zeek-smb-files",
                pivot_label="Open smb_files.log",
                bucket="SMB / RPC",
                timestamp=_safe_float(row.get("ts")),
                focus=path or name,
                log_name="smb_files.log",
                why="SMB file operations are often more useful pivots than generic host rankings when the question is what deserves attention now.",
            )
        )
    for row in smb_mapping_rows[: max(limit, 6)]:
        path = _strip_zeek_value(row.get("path", ""))
        share_type = _strip_zeek_value(row.get("share_type", ""))
        if not path:
            continue
        items.append(
            _attention_item(
                title="SMB share mapping",
                detail=f"{path} • share_type={share_type or 'unknown'}",
                score=3,
                tab="zeek-smb-mapping",
                pivot_label="Open smb_mapping.log",
                bucket="SMB / RPC",
                timestamp=_safe_float(row.get("ts")),
                focus=path,
                log_name="smb_mapping.log",
            )
        )
    for row in dce_rpc_rows[: max(limit, 6)]:
        endpoint = _strip_zeek_value(row.get("endpoint", ""))
        operation = _strip_zeek_value(row.get("operation", ""))
        pipe = _strip_zeek_value(row.get("named_pipe", ""))
        if not any(value for value in (endpoint, operation, pipe)):
            continue
        items.append(
            _attention_item(
                title=f"DCE/RPC activity: {endpoint or operation or 'rpc'}",
                detail=" • ".join(value for value in (operation, pipe) if value),
                score=4,
                tab="zeek-dce-rpc",
                pivot_label="Open dce_rpc.log",
                bucket="SMB / RPC",
                timestamp=_safe_float(row.get("ts")),
                focus=endpoint or operation,
                log_name="dce_rpc.log",
                why="RPC and share access are the sort of concrete investigative events that deserve timeline space over raw first-packet lists.",
            )
        )
    items.sort(key=lambda item: (-item["score"], item.get("timestamp") or 0.0))
    return items[:limit]


def _beacon_like_items(conn_rows: list[dict[str, str]], limit: int = 6) -> list[dict[str, Any]]:
    pair_times: dict[tuple[str, str], list[float]] = {}
    for row in conn_rows:
        ts = _safe_float(row.get("ts"))
        src = _strip_zeek_value(row.get("id.orig_h", ""))
        dst = _strip_zeek_value(row.get("id.resp_h", ""))
        if ts is None or not src or not dst:
            continue
        pair_times.setdefault((src, dst), []).append(ts)
    items: list[dict[str, Any]] = []
    for (src, dst), times in pair_times.items():
        if len(times) < 6:
            continue
        times.sort()
        intervals = [round(times[index + 1] - times[index]) for index in range(len(times) - 1) if times[index + 1] > times[index]]
        if len(intervals) < 5:
            continue
        counts = Counter(intervals)
        interval, count = counts.most_common(1)[0]
        if interval < 10:
            continue
        ratio = count / max(len(intervals), 1)
        if ratio < 0.65:
            continue
        items.append(
            _attention_item(
                title=f"Beacon-like timing: {src} → {dst}",
                detail=f"{len(times)} connections with a repeating ~{interval}s interval ({ratio:.0%} of observed gaps)",
                score=6,
                tab="zeek-conn",
                pivot_label="Open conn.log",
                bucket="Suspicious Flows",
                timestamp=times[0],
                focus=f"{src} -> {dst}",
                log_name="conn.log",
                why="Periodic small relationship timing is one of the strongest anomaly styles borrowed from your pcap_triage workflow.",
            )
        )
    items.sort(key=lambda item: (-item["score"], item.get("timestamp") or 0.0))
    return items[:limit]


def _build_attention_summary(items: list[dict[str, Any]], downranked: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    counts = Counter(item.get("bucket", "Interesting") for item in items)
    facts = [
        {"label": "Interesting signals", "value": str(len(items))},
        {"label": "Buckets hit", "value": str(len(counts))},
        {"label": "Highest-score bucket", "value": counts.most_common(1)[0][0] if counts else "none"},
        {"label": "Down-ranked noise", "value": str(len(downranked))},
    ]
    next_moves = []
    for item in items[:3]:
        next_moves.append(f"{item['title']} → {item['pivot_label']}")
    if not next_moves:
        next_moves.append("This slice does not have a strong standout signal yet; pivot through hosts, conversations, or a later bucket.")
    return facts, next_moves


def _cluster_timeline_items(items: list[dict[str, Any]], limit: int = 18) -> list[dict[str, Any]]:
    timed = [item for item in items if item.get("timestamp") is not None]
    timed.sort(key=lambda item: item.get("timestamp") or 0.0)
    clusters: list[dict[str, Any]] = []
    for item in timed:
        ts = item.get("timestamp")
        if ts is None:
            continue
        if clusters:
            current = clusters[-1]
            same_bucket = current.get("bucket") == item.get("bucket")
            same_tab = current.get("pivot_tab") == item.get("pivot_tab")
            close_in_time = ts - current["end_ts"] <= 45
            if same_bucket and same_tab and close_in_time:
                current["end_ts"] = ts
                current["count"] += 1
                current["details"].append(item["detail"])
                if item.get("focus"):
                    current["focuses"].append(item["focus"])
                current["max_score"] = max(current["max_score"], item["score"])
                continue
        clusters.append(
            {
                "start_ts": ts,
                "end_ts": ts,
                "bucket": item.get("bucket", "Interesting"),
                "pivot_tab": item.get("pivot_tab", ""),
                "pivot_label": item.get("pivot_label", "Open log"),
                "title": item.get("title", "Interesting event"),
                "details": [item.get("detail", "")],
                "focuses": [item.get("focus", "")] if item.get("focus") else [],
                "count": 1,
                "max_score": item.get("score", 0),
                "why": item.get("why", item.get("detail", "")),
            }
        )
    rows: list[dict[str, Any]] = []
    for cluster in clusters[:limit]:
        focuses = [focus for focus in cluster["focuses"] if focus]
        focus_text = ", ".join(list(dict.fromkeys(focuses))[:3]) or cluster["title"]
        summary = cluster["details"][0]
        if cluster["count"] > 1:
            summary = f"{cluster['count']} related events • {summary}"
        rows.append(
            {
                "time_window": _format_epoch_window(cluster["start_ts"], cluster["end_ts"]),
                "event_type": cluster["bucket"],
                "focus": focus_text,
                "summary": summary,
                "why": cluster["why"],
                "pivot_tab": cluster["pivot_tab"],
                "pivot_label": cluster["pivot_label"],
                "score": cluster["max_score"],
            }
        )
    return rows


def _paginate_rows(rows: list[dict[str, Any]], page: int = 1, page_size: int = 25) -> dict[str, Any]:
    total = len(rows)
    page_size = max(1, page_size)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(max(1, page), total_pages)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "rows": rows[start:end],
        "page": page,
        "page_size": page_size,
        "total_rows": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }


def _wildcard_regex(pattern: str) -> re.Pattern[str] | None:
    cleaned = (pattern or "").strip()
    if not cleaned:
        return None
    escaped = re.escape(cleaned).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(escaped, re.IGNORECASE)


def _row_matches_wildcard(row: dict[str, Any], pattern: str) -> bool:
    regex = _wildcard_regex(pattern)
    if not regex:
        return True
    haystack = " ".join(str(value or "") for value in row.values())
    return bool(regex.search(haystack))


def _sort_rows(rows: list[dict[str, Any]], sort_by: str, sort_dir: str = "desc") -> list[dict[str, Any]]:
    if not rows or not sort_by or sort_by not in rows[0]:
        return rows
    reverse = (sort_dir or "desc").lower() == "desc"

    def _key(row: dict[str, Any]) -> tuple[int, Any]:
        value = row.get(sort_by)
        if isinstance(value, (int, float)):
            return (0, value)
        raw = str(value or "").strip()
        try:
            return (0, float(raw.replace(",", "")))
        except Exception:
            return (1, raw.lower())

    return sorted(rows, key=_key, reverse=reverse)


def conversation_page(
    pcap: str,
    page: int = 1,
    page_size: int = 25,
    q: str = "",
    sort_by: str = "connections",
    sort_dir: str = "desc",
) -> dict[str, Any]:
    run_dir = ensure_zeek_logs(pcap)
    conn_rows = parse_zeek_log(run_dir / "conn.log")
    aggregates: dict[tuple[str, str], dict[str, Any]] = {}
    for row in conn_rows:
        left = _strip_zeek_value(row.get("id.orig_h", ""))
        right = _strip_zeek_value(row.get("id.resp_h", ""))
        if not left or not right:
            continue
        key = tuple(sorted((left, right)))
        entry = aggregates.setdefault(
            key,
            {"endpoint_a": key[0], "endpoint_b": key[1], "connections": 0, "orig_bytes": 0, "resp_bytes": 0, "services": Counter(), "first_seen": None, "last_seen": None},
        )
        entry["connections"] += 1
        entry["services"][_conn_service(row)] += 1
        entry["orig_bytes"] += int(_strip_zeek_value(row.get("orig_bytes", "0")) or 0)
        entry["resp_bytes"] += int(_strip_zeek_value(row.get("resp_bytes", "0")) or 0)
        ts = _safe_float(row.get("ts"))
        if ts is not None:
            entry["first_seen"] = ts if entry["first_seen"] is None else min(entry["first_seen"], ts)
            entry["last_seen"] = ts if entry["last_seen"] is None else max(entry["last_seen"], ts)
    rows = []
    for item in aggregates.values():
        top_service = item["services"].most_common(2)
        rows.append(
            {
                "pair": f"{item['endpoint_a']} ↔ {item['endpoint_b']}",
                "connections": item["connections"],
                "bytes": item["orig_bytes"] + item["resp_bytes"],
                "top_services": ", ".join(f"{name} ({count})" for name, count in top_service),
                "first_seen": _format_epoch_window(item["first_seen"]),
                "last_seen": _format_epoch_window(item["last_seen"]),
            }
        )
    if q:
        rows = [row for row in rows if _row_matches_wildcard(row, q)]
    rows = _sort_rows(rows, sort_by=sort_by, sort_dir=sort_dir)
    payload = _paginate_rows(rows, page=page, page_size=page_size)
    payload["columns"] = ["pair", "connections", "bytes", "top_services", "first_seen", "last_seen"]
    payload["sort_by"] = sort_by
    payload["sort_dir"] = sort_dir
    payload["query"] = q
    payload["default_columns"] = payload["columns"]
    return payload


def host_page(
    pcap: str,
    page: int = 1,
    page_size: int = 25,
    q: str = "",
    sort_by: str = "interestingness",
    sort_dir: str = "desc",
) -> dict[str, Any]:
    run_dir = ensure_zeek_logs(pcap)
    conn_rows = parse_zeek_log(run_dir / "conn.log")
    interestingness = _build_ip_interestingness_map(pcap)
    aggregates: dict[str, dict[str, Any]] = {}
    for row in conn_rows:
        src = _strip_zeek_value(row.get("id.orig_h", ""))
        dst = _strip_zeek_value(row.get("id.resp_h", ""))
        if not src or not dst:
            continue
        src_entry = aggregates.setdefault(src, {"ip": src, "connections": 0, "initiated": 0, "responded": 0, "bytes": 0, "peers": Counter(), "services": Counter(), "first_seen": None, "last_seen": None})
        dst_entry = aggregates.setdefault(dst, {"ip": dst, "connections": 0, "initiated": 0, "responded": 0, "bytes": 0, "peers": Counter(), "services": Counter(), "first_seen": None, "last_seen": None})
        for entry, peer, direction in ((src_entry, dst, "initiated"), (dst_entry, src, "responded")):
            entry["connections"] += 1
            entry[direction] += 1
            entry["peers"][peer] += 1
            entry["services"][_conn_service(row)] += 1
            entry["bytes"] += int(_strip_zeek_value(row.get("orig_bytes", "0")) or 0) + int(_strip_zeek_value(row.get("resp_bytes", "0")) or 0)
            ts = _safe_float(row.get("ts"))
            if ts is not None:
                entry["first_seen"] = ts if entry["first_seen"] is None else min(entry["first_seen"], ts)
                entry["last_seen"] = ts if entry["last_seen"] is None else max(entry["last_seen"], ts)
    rows = []
    for item in aggregates.values():
        score = interestingness.get(item["ip"], {})
        peer_text = ", ".join(f"{peer} ({count})" for peer, count in item["peers"].most_common(2))
        service_text = ", ".join(f"{name} ({count})" for name, count in item["services"].most_common(2))
        rows.append(
            {
                "ip": item["ip"],
                "interestingness": score.get("interestingness", 0),
                "confidence": score.get("confidence", "low"),
                "why_high": score.get("why_high", ""),
                "why_low": score.get("why_low", ""),
                "connections": item["connections"],
                "initiated": item["initiated"],
                "responded": item["responded"],
                "peer_count": len(item["peers"]),
                "top_peers": peer_text,
                "top_services": service_text,
                "first_seen": _format_epoch_window(item["first_seen"]),
                "last_seen": _format_epoch_window(item["last_seen"]),
            }
        )
    if q:
        rows = [row for row in rows if _row_matches_wildcard(row, q)]
    rows = _sort_rows(rows, sort_by=sort_by, sort_dir=sort_dir)
    payload = _paginate_rows(rows, page=page, page_size=page_size)
    payload["columns"] = ["ip", "interestingness", "confidence", "why_high", "why_low", "connections", "initiated", "responded", "peer_count", "top_peers", "top_services", "first_seen", "last_seen"]
    payload["sort_by"] = sort_by
    payload["sort_dir"] = sort_dir
    payload["query"] = q
    payload["default_columns"] = ["ip", "interestingness", "confidence", "why_high", "why_low", "connections", "peer_count", "top_peers", "top_services"]
    return payload


def endpoint_page(
    pcap: str,
    page: int = 1,
    page_size: int = 25,
    q: str = "",
    sort_by: str = "interestingness",
    sort_dir: str = "desc",
) -> dict[str, Any]:
    rows = endpoint_stat_rows(pcap)
    interestingness = _build_ip_interestingness_map(pcap)
    enriched_rows = []
    for row in rows:
        ip = row.get("IP", "")
        score = interestingness.get(ip, {})
        enriched_rows.append(
            {
                **row,
                "interestingness": score.get("interestingness", 0),
                "confidence": score.get("confidence", "low"),
                "why_high": score.get("why_high", ""),
                "why_low": score.get("why_low", ""),
            }
        )
    rows = enriched_rows
    if q:
        rows = [row for row in rows if _row_matches_wildcard(row, q)]
    rows = _sort_rows(rows, sort_by=sort_by, sort_dir=sort_dir)
    payload = _paginate_rows(rows, page=page, page_size=page_size)
    payload["columns"] = ["IP", "interestingness", "confidence", "why_high", "why_low", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes"]
    payload["sort_by"] = sort_by
    payload["sort_dir"] = sort_dir
    payload["query"] = q
    payload["default_columns"] = ["IP", "interestingness", "confidence", "why_high", "why_low", "Packets", "Bytes", "Tx Packets", "Rx Packets"]
    return payload


def _rows_preview(rows: list[dict[str, str]], columns: list[str], limit: int = 10) -> list[dict[str, str]]:
    preview: list[dict[str, str]] = []
    for row in rows[:limit]:
        preview.append({column: row.get(column, "") for column in columns})
    return preview


def _row_contains_ip(row: dict[str, str], ip: str) -> bool:
    for value in row.values():
        if value == ip:
            return True
    return False


def _group_top_counts(rows: list[dict[str, str]], fields: list[str], key_name: str, limit: int = 8) -> list[dict[str, Any]]:
    values: list[str] = []
    for row in rows:
        for field in fields:
            value = _strip_zeek_value(row.get(field, ""))
            if value:
                values.append(value)
    return _top_counts(values, key_name=key_name, limit=limit)


def _confidence_label(evidence_points: int) -> str:
    if evidence_points >= 6:
        return "high"
    if evidence_points >= 3:
        return "medium"
    return "low"


def _score_to_suspicion(score: int) -> str:
    if score >= 5:
        return "yes"
    if score >= 1:
        return "possibly"
    return "no"


def _short_reason_text(values: list[str], limit: int = 3) -> str:
    kept = [value for value in values if value][:limit]
    return "; ".join(kept) if kept else ""


def _capture_loss_percent(run_dir: Path) -> float | None:
    rows = parse_zeek_log(run_dir / "capture_loss.log")
    percents: list[float] = []
    for row in rows:
        try:
            percents.append(float(_strip_zeek_value(row.get("percent_lost", "")) or 0.0))
        except Exception:
            continue
    return max(percents) if percents else None


def _http_coverage_gaps(conn_rows: list[dict[str, str]], http_rows: list[dict[str, str]], run_dir: Path) -> list[dict[str, Any]]:
    http_uids = {row.get("uid", "") for row in http_rows if row.get("uid")}
    loss = _capture_loss_percent(run_dir)
    gaps: list[dict[str, Any]] = []
    for row in conn_rows:
        resp_port = _strip_zeek_value(row.get("id.resp_p", ""))
        orig_port = _strip_zeek_value(row.get("id.orig_p", ""))
        service = _conn_service(row)
        uid = row.get("uid", "")
        if uid in http_uids:
            continue
        is_httpish = resp_port in {"80", "8080", "8000", "8888"} or orig_port in {"80", "8080", "8000", "8888"} or service == "http"
        if not is_httpish:
            continue
        history = _strip_zeek_value(row.get("history", ""))
        conn_state = _strip_zeek_value(row.get("conn_state", ""))
        if conn_state != "OTH" and service == "http":
            continue
        hints: list[str] = []
        if conn_state:
            hints.append(f"conn_state={conn_state}")
        if service:
            hints.append(f"service={service}")
        if history:
            hints.append(f"history={history}")
        if loss and loss >= 1.0:
            hints.append(f"capture_loss={loss:.3f}%")
        gaps.append({
            "uid": uid,
            "src": _strip_zeek_value(row.get("id.orig_h", "")),
            "src_port": _strip_zeek_value(row.get("id.orig_p", "")),
            "dest": _strip_zeek_value(row.get("id.resp_h", "")),
            "dest_port": resp_port,
            "summary": f"{_strip_zeek_value(row.get('id.orig_h', ''))}:{_strip_zeek_value(row.get('id.orig_p', ''))} -> {_strip_zeek_value(row.get('id.resp_h', ''))}:{resp_port}",
            "hints": hints,
            "priority": 0 if resp_port == "80" else 1,
        })
    gaps.sort(key=lambda item: (item.get("priority", 9), item.get("dest_port", ""), item.get("summary", "")))
    return gaps[:8]


def _http_gap_packet_fallbacks(pcap: str, gaps: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    if not tshark_available():
        return []
    pcap_path = resolve_pcap(pcap)
    recovered: list[dict[str, Any]] = []
    for gap in gaps:
        if limit and len(recovered) >= limit:
            break
        src = gap.get("src", "")
        src_port = gap.get("src_port", "")
        dest = gap.get("dest", "")
        dest_port = gap.get("dest_port", "")
        if not (src and src_port and dest and dest_port):
            continue
        display_filter = (
            "http && (("
            f"ip.src=={src} && tcp.srcport=={src_port} && ip.dst=={dest} && tcp.dstport=={dest_port}"
            ") || ("
            f"ip.src=={dest} && tcp.srcport=={dest_port} && ip.dst=={src} && tcp.dstport=={src_port}"
            "))"
        )
        proc = run_command([
            "tshark", "-r", str(pcap_path), "-Y", display_filter,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "ip.src",
            "-e", "tcp.srcport",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "http.request.uri",
            "-e", "http.user_agent",
            "-e", "http.response.code",
            "-e", "http.content_type",
        ])
        if proc.returncode != 0 or not proc.stdout.strip():
            continue
        pending: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            parts += [""] * (13 - len(parts))
            ts, frame, stream, row_src, row_src_port, row_dest, row_dest_port, row_method, row_host, row_uri, row_ua, row_code, row_type = parts[:13]
            ts_text = _strip_zeek_value(ts)
            frame_text = _strip_zeek_value(frame)
            stream_text = _strip_zeek_value(stream)
            method = _strip_zeek_value(row_method)
            host = _strip_zeek_value(row_host)
            uri = _strip_zeek_value(row_uri)
            user_agent = _strip_zeek_value(row_ua)
            response_code = _strip_zeek_value(row_code)
            content_type = _strip_zeek_value(row_type)
            if method or host or uri:
                pending.append({
                    "summary": gap.get("summary"),
                    "uid": gap.get("uid"),
                    "ts": ts_text,
                    "request_frame": frame_text,
                    "response_frame": "",
                    "frames": [value for value in [frame_text] if value],
                    "streams": [value for value in [stream_text] if value],
                    "stream": stream_text,
                    "src": _strip_zeek_value(row_src) or str(src),
                    "src_port": _strip_zeek_value(row_src_port) or str(src_port),
                    "dest": _strip_zeek_value(row_dest) or str(dest),
                    "dest_port": _strip_zeek_value(row_dest_port) or str(dest_port),
                    "method": method,
                    "host": host,
                    "uri": uri,
                    "user_agent": user_agent,
                    "response_code": "",
                    "content_type": "",
                })
                continue
            if response_code or content_type:
                target = next((item for item in reversed(pending) if not item.get("response_code") and item.get("stream") == stream_text), None)
                if target is None:
                    pending.append({
                        "summary": gap.get("summary"),
                        "uid": gap.get("uid"),
                        "ts": ts_text,
                        "request_frame": "",
                        "response_frame": frame_text,
                        "frames": [value for value in [frame_text] if value],
                        "streams": [value for value in [stream_text] if value],
                        "stream": stream_text,
                        "src": str(src),
                        "src_port": str(src_port),
                        "dest": str(dest),
                        "dest_port": str(dest_port),
                        "method": "",
                        "host": "",
                        "uri": "",
                        "user_agent": "",
                        "response_code": response_code,
                        "content_type": content_type,
                    })
                else:
                    if frame_text and frame_text not in target["frames"]:
                        target["frames"].append(frame_text)
                    if stream_text and stream_text not in target["streams"]:
                        target["streams"].append(stream_text)
                    target["response_frame"] = frame_text or target.get("response_frame", "")
                    target["response_code"] = target.get("response_code") or response_code
                    target["content_type"] = target.get("content_type") or content_type
        for item in pending:
            recovered.append(item)
            if limit and len(recovered) >= limit:
                break
    return recovered


def _interestingness_label(score: int) -> str:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _build_ip_interestingness_map(pcap: str) -> dict[str, dict[str, Any]]:
    run_dir = ensure_zeek_logs(pcap)
    conn_rows = parse_zeek_log(run_dir / "conn.log")
    dns_rows = parse_zeek_log(run_dir / "dns.log")
    http_rows = parse_zeek_log(run_dir / "http.log")
    files_rows = parse_zeek_log(run_dir / "files.log")
    ssl_rows = parse_zeek_log(run_dir / "ssl.log")
    notice_rows = parse_zeek_log(run_dir / "notice.log")
    weird_rows = parse_zeek_log(run_dir / "weird.log")
    smb_files_rows = parse_zeek_log(run_dir / "smb_files.log")
    dce_rpc_rows = parse_zeek_log(run_dir / "dce_rpc.log")
    software_rows = parse_zeek_log(run_dir / "software.log")

    summary: dict[str, dict[str, Any]] = {}

    def ensure(ip: str) -> dict[str, Any]:
        return summary.setdefault(
            ip,
            {
                "ip": ip,
                "conn_count": 0,
                "initiated": 0,
                "responded": 0,
                "bytes": 0,
                "peers": Counter(),
                "public_peers": set(),
                "services": Counter(),
                "notice_hits": 0,
                "weird_hits": 0,
                "dns_hits": 0,
                "dns_failures": 0,
                "dns_entropy_hits": 0,
                "http_hits": 0,
                "http_error_hits": 0,
                "http_odd_agent_hits": 0,
                "file_hits": 0,
                "macro_file_hits": 0,
                "ssl_hits": 0,
                "ssl_validation_hits": 0,
                "smb_hits": 0,
                "rpc_hits": 0,
                "software_hits": 0,
                "beacon_hits": 0,
            },
        )

    pair_times: dict[tuple[str, str], list[float]] = {}
    for row in conn_rows:
        src = _strip_zeek_value(row.get("id.orig_h", ""))
        dst = _strip_zeek_value(row.get("id.resp_h", ""))
        if not src or not dst:
            continue
        ts = _safe_float(row.get("ts"))
        src_entry = ensure(src)
        dst_entry = ensure(dst)
        byte_count = int(_strip_zeek_value(row.get("orig_bytes", "0")) or 0) + int(_strip_zeek_value(row.get("resp_bytes", "0")) or 0)
        service = _conn_service(row)
        for entry, peer, direction in ((src_entry, dst, "initiated"), (dst_entry, src, "responded")):
            entry["conn_count"] += 1
            entry[direction] += 1
            entry["bytes"] += byte_count
            entry["peers"][peer] += 1
            entry["services"][service] += 1
            if is_public_ip(peer):
                entry["public_peers"].add(peer)
        if ts is not None:
            pair_times.setdefault((src, dst), []).append(ts)

    for item in _beacon_like_items(conn_rows, limit=max(20, len(pair_times))):
        focus = item.get("focus", "")
        if " -> " not in focus:
            continue
        src, dst = [part.strip() for part in focus.split(" -> ", 1)]
        if src in summary:
            summary[src]["beacon_hits"] += 1
        if dst in summary:
            summary[dst]["beacon_hits"] += 1

    for row in dns_rows:
        ips = [_strip_zeek_value(row.get("id.orig_h", "")), _strip_zeek_value(row.get("id.resp_h", ""))]
        query = _strip_zeek_value(row.get("query", ""))
        for ip in [ip for ip in ips if ip]:
            entry = ensure(ip)
            entry["dns_hits"] += 1
            rcode = _strip_zeek_value(row.get("rcode_name", ""))
            if rcode and rcode != "NOERROR":
                entry["dns_failures"] += 1
            if len(query) > 40 or _entropy(query) > 4.0:
                entry["dns_entropy_hits"] += 1

    for row in http_rows:
        ips = [_strip_zeek_value(row.get("id.orig_h", "")), _strip_zeek_value(row.get("id.resp_h", ""))]
        for ip in [ip for ip in ips if ip]:
            entry = ensure(ip)
            entry["http_hits"] += 1
            if _http_status_is_error(row.get("status_code", "")):
                entry["http_error_hits"] += 1
            if _is_unusual_user_agent(row.get("user_agent", "")):
                entry["http_odd_agent_hits"] += 1

    for row in files_rows:
        ips = [
            _strip_zeek_value(row.get("id.orig_h", "")),
            _strip_zeek_value(row.get("id.resp_h", "")),
            _strip_zeek_value(row.get("tx_hosts", "")),
            _strip_zeek_value(row.get("rx_hosts", "")),
        ]
        filename = _strip_zeek_value(row.get("filename", ""))
        extension = Path(filename).suffix.lower() if filename else ""
        mime_type = _strip_zeek_value(row.get("mime_type", ""))
        for ip in [ip for ip in ips if ip]:
            entry = ensure(ip)
            entry["file_hits"] += 1
            if extension in MACRO_EXTENSIONS or (mime_type and mime_type not in BORING_FILE_MIME_HINTS):
                entry["macro_file_hits"] += 1

    for row in ssl_rows:
        ips = [_strip_zeek_value(row.get("id.orig_h", "")), _strip_zeek_value(row.get("id.resp_h", ""))]
        for ip in [ip for ip in ips if ip]:
            entry = ensure(ip)
            entry["ssl_hits"] += 1
            validation_status = _strip_zeek_value(row.get("validation_status", ""))
            if validation_status and validation_status != "ok" and not any(token in validation_status.lower() for token in ("certificate", "self signed", "issuer")):
                entry["ssl_validation_hits"] += 1

    for row in notice_rows:
        if _is_likely_noise_notice(row):
            continue
        ips = [_strip_zeek_value(row.get("src", "")), _strip_zeek_value(row.get("dst", ""))]
        for ip in [ip for ip in ips if ip]:
            ensure(ip)["notice_hits"] += 1

    for row in weird_rows:
        if _is_likely_noise_weird(row):
            continue
        ips = [_strip_zeek_value(row.get("id.orig_h", "")), _strip_zeek_value(row.get("id.resp_h", ""))]
        for ip in [ip for ip in ips if ip]:
            ensure(ip)["weird_hits"] += 1

    for row in smb_files_rows:
        ips = [_strip_zeek_value(row.get("id.orig_h", "")), _strip_zeek_value(row.get("id.resp_h", ""))]
        for ip in [ip for ip in ips if ip]:
            ensure(ip)["smb_hits"] += 1

    for row in dce_rpc_rows:
        ips = [_strip_zeek_value(row.get("id.orig_h", "")), _strip_zeek_value(row.get("id.resp_h", ""))]
        for ip in [ip for ip in ips if ip]:
            ensure(ip)["rpc_hits"] += 1

    for row in software_rows:
        ip = _strip_zeek_value(row.get("host", ""))
        if ip:
            ensure(ip)["software_hits"] += 1

    result: dict[str, dict[str, Any]] = {}
    for ip, item in summary.items():
        up: list[str] = []
        down: list[str] = []
        score = 0

        top_service = item["services"].most_common(1)
        dns_heavy = False
        if top_service:
            service_name, service_count = top_service[0]
            dns_heavy = service_name == "dns" and service_count >= max(20, int(item["conn_count"] * 0.7))

        if item["notice_hits"]:
            score += min(item["notice_hits"] * 3, 6)
            up.append(f"{item['notice_hits']} notice hits")
        if item["weird_hits"]:
            weird_credit = 1 if dns_heavy else min(item["weird_hits"], 2)
            score += weird_credit
            up.append(f"{item['weird_hits']} non-noise weird hits")
        if item["dns_failures"] and not dns_heavy:
            score += min(item["dns_failures"], 2)
            up.append(f"{item['dns_failures']} DNS failures")
        if item["dns_entropy_hits"] and not dns_heavy:
            score += min(item["dns_entropy_hits"], 2)
            up.append(f"{item['dns_entropy_hits']} long/high-entropy DNS lookups")
        if item["http_error_hits"]:
            score += min(item["http_error_hits"], 2)
            up.append(f"{item['http_error_hits']} HTTP error responses")
        if item["http_odd_agent_hits"]:
            score += min(item["http_odd_agent_hits"], 2)
            up.append(f"{item['http_odd_agent_hits']} unusual HTTP user-agent sightings")
        if item["macro_file_hits"]:
            score += min(item["macro_file_hits"] * 2, 4)
            up.append(f"{item['macro_file_hits']} suspicious file-transfer indicators")
        elif item["file_hits"]:
            score += 1
            up.append(f"{item['file_hits']} file-transfer hits")
        if item["beacon_hits"]:
            score += min(item["beacon_hits"] * 3, 6)
            up.append(f"{item['beacon_hits']} beacon-like timing relationships")
        if item["smb_hits"]:
            score += min(item["smb_hits"], 3)
            up.append(f"{item['smb_hits']} SMB file events")
        if item["rpc_hits"]:
            score += min(item["rpc_hits"], 3)
            up.append(f"{item['rpc_hits']} DCE/RPC events")
        if len(item["public_peers"]) >= 2 and item["initiated"] >= item["responded"]:
            score += 2
            up.append(f"initiates to {len(item['public_peers'])} public peers")
        elif len(item["public_peers"]) == 1 and item["initiated"]:
            score += 1
            up.append("initiates to a public peer")
        if len(item["peers"]) >= 8:
            score += 1
            up.append(f"talks to {len(item['peers'])} unique peers")
        cross_log_count = sum(1 for key in ("dns_hits", "http_hits", "file_hits", "ssl_hits", "smb_hits", "rpc_hits", "software_hits", "notice_hits", "weird_hits") if item[key])
        if cross_log_count >= 4:
            score += 2
            up.append(f"appears across {cross_log_count} log areas")
        elif cross_log_count >= 2:
            score += 1
            up.append(f"appears across {cross_log_count} log areas")

        if top_service:
            service_name, service_count = top_service[0]
            if dns_heavy:
                score -= 4
                down.append("looks DNS-heavy / possibly infrastructure")
            elif service_name in {"kerberos", "ldap", "dns", "ssl", "http", "smb"} and service_count >= max(10, int(item["conn_count"] * 0.7)):
                score -= 1
                down.append(f"activity is concentrated in common service {service_name}")
        if item["responded"] and item["initiated"] == 0:
            score -= 1
            down.append("only appears as responder in this slice")
        if item["conn_count"] < 5 and not up:
            down.append("very low signal volume")

        evidence_points = sum(
            1
            for value in (
                item["conn_count"],
                item["notice_hits"],
                item["weird_hits"],
                item["dns_hits"],
                item["http_hits"],
                item["file_hits"],
                item["ssl_hits"],
                item["smb_hits"],
                item["rpc_hits"],
                item["software_hits"],
                item["beacon_hits"],
            )
            if value
        )
        confidence = _confidence_label(evidence_points)
        result[ip] = {
            "interestingness": score,
            "interestingness_label": _interestingness_label(score),
            "confidence": confidence,
            "why_high": _short_reason_text(up),
            "why_low": _short_reason_text(down),
            "reasons_up": up,
            "reasons_down": down,
            "summary": item,
        }
    return result


def _zeek_triage_sections(metadata: dict[str, Any], zeek: dict[str, Any]) -> list[dict[str, Any]]:
    parsed = metadata.get("parsed", {}) if isinstance(metadata, dict) else {}
    sections: list[dict[str, Any]] = [
        {
            "title": "Immediate Read",
            "kind": "facts",
            "items": [
                {"label": "Packets", "value": parsed.get("number_of_packets", "n/a")},
                {"label": "Duration", "value": parsed.get("capture_duration", "n/a")},
                {"label": "Earliest", "value": parsed.get("earliest_packet_time", "n/a")},
                {"label": "Latest", "value": parsed.get("latest_packet_time", "n/a")},
                {"label": "Interesting", "value": str(len(zeek.get("interesting_attention", [])))},
                {"label": "Down-ranked noise", "value": str(len(zeek.get("downranked_noise", [])))},
            ],
        },
    ]
    if not zeek.get("ready"):
        sections.append(
            {
                "title": "Zeek Status",
                "kind": "lines",
                "items": [zeek.get("error", "Zeek summary is not ready yet.")],
            }
        )
        return sections

    sections.extend([
        {
            "title": "Interesting Signals",
            "kind": "attention",
            "items": zeek.get("interesting_attention", []),
        },
        {
            "title": "Immediate Attention Summary",
            "kind": "facts",
            "items": zeek.get("attention_summary", []),
        },
        {
            "title": "Best Next Pivots",
            "kind": "lines",
            "items": zeek.get("attention_next_moves", []),
        },
        _add_pivots(
            {
                "title": "Down-Ranked Exercise Noise",
                "kind": "lines",
                "items": zeek.get("downranked_noise", []),
            },
            {"label": "Open notice.log", "tab": "zeek-notice"},
            {"label": "Open weird.log", "tab": "zeek-weird"},
            {"label": "Open ssl.log", "tab": "zeek-ssl"},
        ),
    ])
    return sections


def zeek_summary(pcap: str) -> dict[str, Any]:
    run_dir = ensure_zeek_logs(pcap)
    logs = sorted(path.name for path in run_dir.glob("*.log"))
    conn_rows = parse_zeek_log(run_dir / "conn.log")
    dns_rows = parse_zeek_log(run_dir / "dns.log")
    http_rows = parse_zeek_log(run_dir / "http.log")
    files_rows = parse_zeek_log(run_dir / "files.log")
    notice_rows = parse_zeek_log(run_dir / "notice.log")
    weird_rows = parse_zeek_log(run_dir / "weird.log")
    ssl_rows = parse_zeek_log(run_dir / "ssl.log")
    x509_rows = parse_zeek_log(run_dir / "x509.log")
    smtp_rows = parse_zeek_log(run_dir / "smtp.log")
    smb_files_rows = parse_zeek_log(run_dir / "smb_files.log")
    smb_mapping_rows = parse_zeek_log(run_dir / "smb_mapping.log")
    dce_rpc_rows = parse_zeek_log(run_dir / "dce_rpc.log")
    http_coverage_gaps = _http_coverage_gaps(conn_rows, http_rows, run_dir)
    http_gap_packet_fallbacks = _http_gap_packet_fallbacks(pcap, http_coverage_gaps)

    service_counts = Counter(_conn_service(row) for row in conn_rows)
    pair_counts = Counter(
        f"{row.get('id.orig_h', '?')} -> {row.get('id.resp_h', '?')}"
        for row in conn_rows
        if row.get("id.orig_h") or row.get("id.resp_h")
    )
    external_counts = Counter(
        row.get("id.resp_h", "")
        for row in conn_rows
        if is_public_ip(row.get("id.resp_h", ""))
    )
    log_counts = {
        name: len(parse_zeek_log(run_dir / name))
        for name in logs
    }

    dns_preview = [
        {
            "query": row.get("query", ""),
            "qtype_name": row.get("qtype_name", ""),
            "rcode_name": row.get("rcode_name", ""),
            "answers": row.get("answers", ""),
        }
        for row in dns_rows[:10]
    ]
    file_packet_fallbacks = files_log_fallback_rows(pcap, limit=12)
    ssl_packet_fallbacks = ssl_log_fallback_rows(pcap, limit=12) if not ssl_rows else []
    http_preview = [
        {
            "host": row.get("host", ""),
            "uri": row.get("uri", ""),
            "method": row.get("method", ""),
            "status_code": row.get("status_code", ""),
            "user_agent": row.get("user_agent", ""),
            "source": row.get("source", ""),
        }
        for row in (http_rows + [_http_fallback_item_to_log_row(item) for item in http_gap_packet_fallbacks])[:10]
    ]
    file_preview = [
        {
            "source": row.get("source", ""),
            "mime_type": row.get("mime_type", ""),
            "filename": row.get("filename", ""),
            "seen_bytes": row.get("seen_bytes", ""),
            "sha256": row.get("sha256", ""),
            "uri": row.get("uri", ""),
        }
        for row in (files_rows + file_packet_fallbacks)[:10]
    ]
    weird_preview = [
        {
            "name": row.get("name", ""),
            "addl": row.get("addl", ""),
            "uid": row.get("uid", ""),
        }
        for row in weird_rows[:10]
    ]
    notice_preview = [
        {
            "note": row.get("note", ""),
            "msg": row.get("msg", ""),
            "sub": row.get("sub", ""),
            "src": row.get("src", ""),
            "dst": row.get("dst", ""),
        }
        for row in notice_rows[:10]
    ]
    ssl_preview = [
        {
            "server_name": row.get("server_name", ""),
            "subject": row.get("subject", ""),
            "issuer": row.get("issuer", ""),
            "version": row.get("version", ""),
            "cipher": row.get("cipher", ""),
            "handshake_type": row.get("handshake_type", ""),
            "source": row.get("source", ""),
        }
        for row in (ssl_rows + ssl_packet_fallbacks)[:10]
    ]
    x509_preview = _rows_preview(
        x509_rows,
        ["certificate.version", "certificate.subject", "certificate.issuer", "san.dns", "basic_constraints.ca"],
    )
    smtp_preview = _rows_preview(
        smtp_rows,
        ["mailfrom", "rcptto", "subject", "user_agent", "last_reply"],
    )
    smb_files_preview = _rows_preview(
        smb_files_rows,
        ["action", "path", "name", "size", "times.modified"],
    )
    smb_mapping_preview = _rows_preview(
        smb_mapping_rows,
        ["path", "service", "native_file_system", "share_type"],
    )
    dce_rpc_preview = _rows_preview(
        dce_rpc_rows,
        ["rtt", "named_pipe", "endpoint", "operation"],
    )
    dns_queries = _top_counts([_strip_zeek_value(row.get("query", "")) for row in dns_rows], key_name="query")
    http_hosts = _top_counts([_strip_zeek_value(row.get("host", "")) for row in (http_rows + [_http_fallback_item_to_log_row(item) for item in http_gap_packet_fallbacks])], key_name="host")
    mime_source_counts: Counter[tuple[str, str, str]] = Counter()
    for row in files_rows + file_packet_fallbacks:
        for mime in _split_zeek_multi_value(row.get("mime_type", "")):
            mime_source_counts[(mime, "files.log", "mime_type")] += 1
    for row in http_rows:
        for field_name in ("resp_mime_types", "orig_mime_types"):
            for mime in _split_zeek_multi_value(row.get(field_name, "")):
                mime_source_counts[(mime, "http.log", field_name)] += 1
    file_mimes = [
        {
            "mime_type": mime,
            "count": count,
            "log_name": log_name,
            "source_field": field_name,
        }
        for (mime, log_name, field_name), count in mime_source_counts.most_common(10)
    ]
    dns_failures_preview = _dns_failure_rows(dns_rows)
    http_errors_preview = _http_error_rows(http_rows)
    smb_activity_preview = _top_counts(
        [
            " | ".join(
                filter(
                    None,
                    [
                        _strip_zeek_value(row.get("action", "")),
                        _strip_zeek_value(row.get("path", "")),
                        _strip_zeek_value(row.get("name", "")),
                    ],
                )
            )
            for row in smb_files_rows
        ],
        key_name="value",
    )
    smb_activity_preview = [
        {
            "action": item["value"].split(" | ")[0] if item.get("value") else "",
            "path": item["value"].split(" | ")[1] if item.get("value") and len(item["value"].split(" | ")) > 1 else "",
            "name": item["value"].split(" | ")[2] if item.get("value") and len(item["value"].split(" | ")) > 2 else "",
            "count": item["count"],
        }
        for item in smb_activity_preview
    ]
    dce_rpc_activity_preview = _top_counts(
        [
            " | ".join(
                filter(
                    None,
                    [
                        _strip_zeek_value(row.get("endpoint", "")),
                        _strip_zeek_value(row.get("operation", "")),
                        _strip_zeek_value(row.get("named_pipe", "")),
                    ],
                )
            )
            for row in dce_rpc_rows
        ],
        key_name="value",
    )
    dce_rpc_activity_preview = [
        {
            "endpoint": item["value"].split(" | ")[0] if item.get("value") else "",
            "operation": item["value"].split(" | ")[1] if item.get("value") and len(item["value"].split(" | ")) > 1 else "",
            "named_pipe": item["value"].split(" | ")[2] if item.get("value") and len(item["value"].split(" | ")) > 2 else "",
            "count": item["count"],
        }
        for item in dce_rpc_activity_preview
    ]
    dns_attention = _interesting_dns_items(dns_rows)
    http_attention = _interesting_http_items(http_rows + [_with_log_aliases(_http_fallback_item_to_log_row(item)) for item in http_gap_packet_fallbacks])
    file_attention = _interesting_file_items(files_rows)
    tls_attention, tls_noise = _interesting_tls_items(ssl_rows, x509_rows)
    notice_weird_attention, notice_weird_noise = _interesting_notice_weird_items(notice_rows, weird_rows)
    smb_rpc_attention = _interesting_smb_rpc_items(smb_files_rows, smb_mapping_rows, dce_rpc_rows)
    beacon_attention = _beacon_like_items(conn_rows)
    interesting_attention = sorted(
        dns_attention + http_attention + file_attention + tls_attention + notice_weird_attention + smb_rpc_attention + beacon_attention,
        key=lambda item: (-item["score"], item.get("timestamp") or 0.0),
    )
    interesting_attention = interesting_attention[:16]
    downranked_noise = (tls_noise + notice_weird_noise)[:8]
    attention_summary, next_moves = _build_attention_summary(interesting_attention, downranked_noise)
    event_timeline = _cluster_timeline_items(interesting_attention)

    return {
        "ready": True,
        "run_dir": str(run_dir),
        "logs": logs,
        "log_counts": log_counts,
        "conn_count": len(conn_rows),
        "top_services": [{"name": name, "count": count} for name, count in service_counts.most_common(8)],
        "top_pairs": [{"pair": pair, "count": count} for pair, count in pair_counts.most_common(8)],
        "external_destinations": [{"ip": ip, "count": count} for ip, count in external_counts.most_common(8)],
        "notice_preview": notice_preview,
        "weird_preview": weird_preview,
        "dns_preview": dns_preview,
        "http_preview": http_preview,
        "file_preview": file_preview,
        "ssl_preview": ssl_preview,
        "x509_preview": x509_preview,
        "smtp_preview": smtp_preview,
        "smb_files_preview": smb_files_preview,
        "smb_mapping_preview": smb_mapping_preview,
        "dce_rpc_preview": dce_rpc_preview,
        "http_coverage_gaps": http_coverage_gaps,
        "http_gap_packet_fallbacks": http_gap_packet_fallbacks,
        "file_packet_fallbacks": file_packet_fallbacks,
        "ssl_packet_fallbacks": ssl_packet_fallbacks,
        "capture_loss_percent": _capture_loss_percent(run_dir),
        "top_dns_queries": dns_queries,
        "top_http_hosts": http_hosts,
        "top_file_mime_types": file_mimes,
        "dns_failures_preview": dns_failures_preview,
        "http_errors_preview": http_errors_preview,
        "smb_activity_preview": smb_activity_preview,
        "dce_rpc_activity_preview": dce_rpc_activity_preview,
        "interesting_attention": interesting_attention,
        "downranked_noise": downranked_noise,
        "attention_summary": attention_summary,
        "attention_next_moves": next_moves,
        "event_timeline": event_timeline,
        "conn_preview": conn_rows[:20],
    }


def zeek_endpoint_activity(pcap: str, ip: str) -> dict[str, Any]:
    run_dir = ensure_zeek_logs(pcap)
    conn_rows = parse_zeek_log(run_dir / "conn.log")
    matched = [
        row for row in conn_rows
        if row.get("id.orig_h") == ip or row.get("id.resp_h") == ip
    ]
    if not matched:
        return {
            "ip": ip,
            "conn_count": 0,
            "first_seen": None,
            "last_seen": None,
            "top_peers": [],
            "top_services": [],
            "initiated_count": 0,
            "responded_count": 0,
            "preview": [],
            "summary_text": f"Zeek conn.log did not show any activity for {ip} in this capture.",
        }

    peer_counts = Counter()
    service_counts = Counter()
    initiated_count = 0
    responded_count = 0
    timestamps: list[str] = []
    preview: list[dict[str, str]] = []
    for row in matched:
        timestamps.append(row.get("ts", ""))
        if row.get("id.orig_h") == ip:
            initiated_count += 1
            peer = row.get("id.resp_h", "?")
        else:
            responded_count += 1
            peer = row.get("id.orig_h", "?")
        peer_counts[peer] += 1
        service_counts[_conn_service(row)] += 1
        if len(preview) < 16:
            preview.append(
                {
                    "ts": row.get("ts", ""),
                    "uid": row.get("uid", ""),
                    "id.orig_h": row.get("id.orig_h", ""),
                    "id.orig_p": row.get("id.orig_p", ""),
                    "id.resp_h": row.get("id.resp_h", ""),
                    "id.resp_p": row.get("id.resp_p", ""),
                    "proto": row.get("proto", ""),
                    "service": row.get("service", ""),
                    "conn_state": row.get("conn_state", ""),
                    "orig_bytes": row.get("orig_bytes", ""),
                    "resp_bytes": row.get("resp_bytes", ""),
                }
            )

    summary_bits = [f"Zeek saw {len(matched)} connections involving {ip}."]
    if initiated_count or responded_count:
        summary_bits.append(f"Roles: initiated {initiated_count}, responded {responded_count}.")
    if peer_counts:
        peer_text = ", ".join(f"{peer} ({count})" for peer, count in peer_counts.most_common(5))
        summary_bits.append(f"Top peers: {peer_text}.")
    if service_counts:
        service_text = ", ".join(f"{name} ({count})" for name, count in service_counts.most_common(5))
        summary_bits.append(f"Top services: {service_text}.")

    return {
        "ip": ip,
        "conn_count": len(matched),
        "first_seen": min((ts for ts in timestamps if ts), default=None),
        "last_seen": max((ts for ts in timestamps if ts), default=None),
        "top_peers": [{"peer": peer, "count": count} for peer, count in peer_counts.most_common(8)],
        "top_services": [{"name": name, "count": count} for name, count in service_counts.most_common(8)],
        "initiated_count": initiated_count,
        "responded_count": responded_count,
        "preview": preview,
        "summary_text": " ".join(summary_bits),
    }


def zeek_ip_profile(pcap: str, ip: str) -> dict[str, Any]:
    run_dir = ensure_zeek_logs(pcap)
    endpoint = zeek_endpoint_activity(pcap, ip)
    log_specs = {
        "dns.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name", "answers"]},
        "http.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "method", "host", "uri", "status_code", "user_agent"]},
        "files.log": {"preview_fields": ["ts", "source", "mime_type", "filename", "seen_bytes", "sha256"]},
        "ssl.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "server_name", "version", "cipher", "validation_status"]},
        "x509.log": {"preview_fields": ["ts", "certificate.subject", "certificate.issuer", "san.dns", "san.ip"]},
        "notice.log": {"preview_fields": ["ts", "src", "dst", "note", "msg", "sub"]},
        "weird.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "name", "addl", "source"]},
        "smtp.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "helo", "mailfrom", "rcptto", "last_reply", "tls"]},
        "smb_files.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "action", "path", "name", "size"]},
        "smb_mapping.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "path", "share_type", "service"]},
        "dce_rpc.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "endpoint", "operation", "named_pipe", "rtt"]},
        "ldap.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "message_id", "version", "opcode", "result"]},
        "kerberos.log": {"preview_fields": ["ts", "id.orig_h", "id.resp_h", "request_type", "service", "client", "success"]},
    }

    matches_by_log: dict[str, dict[str, Any]] = {}
    suspicion_reasons: list[str] = []
    benign_signals: list[str] = []

    for log_name, spec in log_specs.items():
        rows = parse_zeek_log(run_dir / log_name)
        matched = [row for row in rows if _row_contains_ip(row, ip)]
        if not matched:
            continue
        matches_by_log[log_name] = {
            "count": len(matched),
            "preview": _rows_preview(matched, spec["preview_fields"], limit=10),
        }

    dns_rows = parse_zeek_log(run_dir / "dns.log")
    dns_matched = [row for row in dns_rows if _row_contains_ip(row, ip)]
    http_rows = parse_zeek_log(run_dir / "http.log")
    http_matched = [row for row in http_rows if _row_contains_ip(row, ip)]
    http_fallback_rows = [row for row in http_log_fallback_rows(pcap, limit=20) if _row_contains_ip(row, ip)]
    files_rows = parse_zeek_log(run_dir / "files.log")
    files_matched = [row for row in files_rows if _row_contains_ip(row, ip)]
    file_fallback_rows = [row for row in files_log_fallback_rows(pcap, limit=20) if _row_contains_ip(row, ip)]
    ssl_rows = parse_zeek_log(run_dir / "ssl.log")
    ssl_matched = [row for row in ssl_rows if _row_contains_ip(row, ip)]
    ssl_fallback_rows = [row for row in ssl_log_fallback_rows(pcap, limit=20) if _row_contains_ip(row, ip)]
    notice_rows = parse_zeek_log(run_dir / "notice.log")
    notice_matched = [row for row in notice_rows if _row_contains_ip(row, ip)]
    weird_rows = parse_zeek_log(run_dir / "weird.log")
    weird_matched = [row for row in weird_rows if _row_contains_ip(row, ip)]
    smb_files_rows = parse_zeek_log(run_dir / "smb_files.log")
    smb_files_matched = [row for row in smb_files_rows if _row_contains_ip(row, ip)]
    dce_rpc_rows = parse_zeek_log(run_dir / "dce_rpc.log")
    dce_rpc_matched = [row for row in dce_rpc_rows if _row_contains_ip(row, ip)]

    top_dns_queries = _group_top_counts(dns_matched, ["query"], "query")
    top_http_hosts = _group_top_counts(http_matched + http_fallback_rows, ["host"], "host")
    top_file_names = _group_top_counts(files_matched + file_fallback_rows + smb_files_matched, ["filename", "name", "path"], "artifact")
    notice_types = _group_top_counts(notice_matched, ["note"], "note")
    weird_types = _group_top_counts(weird_matched, ["name"], "name")
    dce_rpc_ops = _group_top_counts(dce_rpc_matched, ["endpoint", "operation"], "operation")

    public_peers = {
        row.get("id.resp_h", "")
        for row in endpoint.get("preview", [])
        if row.get("id.orig_h") == ip and is_public_ip(row.get("id.resp_h", ""))
    }
    public_peers.update(
        {
            row.get("id.orig_h", "")
            for row in endpoint.get("preview", [])
            if row.get("id.resp_h") == ip and is_public_ip(row.get("id.orig_h", ""))
        }
    )

    if notice_matched:
        suspicion_reasons.append(f"notice.log contains {len(notice_matched)} event(s) tied to {ip}")
    if weird_matched:
        suspicion_reasons.append(f"weird.log contains {len(weird_matched)} event(s) tied to {ip}")
    if any(_http_status_is_error(row.get("status_code", "")) for row in http_matched):
        suspicion_reasons.append("http.log shows HTTP/proxy error responses tied to this IP")
    if http_fallback_rows:
        suspicion_reasons.append(f"packet fallback recovered {len(http_fallback_rows)} HTTP row(s) that Zeek http.log missed")
    if file_fallback_rows:
        suspicion_reasons.append(f"packet fallback recovered {len(file_fallback_rows)} file/artifact row(s) tied to this IP")
    if any(_strip_zeek_value(row.get("validation_status", "")) not in {"", "ok"} for row in ssl_matched):
        suspicion_reasons.append("ssl.log shows non-empty TLS validation status tied to this IP")
    if ssl_fallback_rows and not ssl_matched:
        suspicion_reasons.append(f"packet fallback recovered {len(ssl_fallback_rows)} TLS handshake row(s) tied to this IP")

    if endpoint.get("responded_count", 0) >= max(10, endpoint.get("initiated_count", 0) * 4) and not notice_matched:
        benign_signals.append("role split is strongly service-side rather than client-side")
    if endpoint.get("top_services"):
        dominant_service = endpoint["top_services"][0]["name"]
        dominant_count = endpoint["top_services"][0]["count"]
        if dominant_count >= max(10, endpoint.get("conn_count", 0) // 2) and dominant_service in {"ssl", "http", "dns", "tcp", "kerberos", "ldap", "smb"}:
            benign_signals.append(f"activity is concentrated in one common service ({dominant_service})")
    if endpoint.get("responded_count", 0) and endpoint.get("initiated_count", 0) == 0 and not suspicion_reasons:
        benign_signals.append("the IP only appears as a responder in this slice")

    score = 0
    score += min(len(notice_matched) * 3, 6)
    score += min(len(weird_matched), 2)
    if any(_http_status_is_error(row.get("status_code", "")) for row in http_matched):
        score += 1
    if http_fallback_rows:
        score += 2
    if file_fallback_rows:
        score += 1
    if any(_strip_zeek_value(row.get("validation_status", "")) not in {"", "ok"} for row in ssl_matched):
        score += 1
    if ssl_fallback_rows and not ssl_matched:
        score += 1
    if len(public_peers) >= 2 and endpoint.get("initiated_count", 0) >= endpoint.get("responded_count", 0):
        score += 2
    elif len(public_peers) == 1 and endpoint.get("initiated_count", 0):
        score += 1
    if endpoint.get("initiated_count", 0) >= max(5, endpoint.get("responded_count", 0) * 2):
        score += 1

    if endpoint.get("responded_count", 0) >= max(10, endpoint.get("initiated_count", 0) * 4):
        score -= 2
    if endpoint.get("responded_count", 0) and endpoint.get("initiated_count", 0) == 0:
        score -= 1
    if endpoint.get("top_services"):
        dominant_service = endpoint["top_services"][0]["name"]
        dominant_count = endpoint["top_services"][0]["count"]
        if dominant_count >= max(10, endpoint.get("conn_count", 0) // 2) and dominant_service in {"ssl", "http", "dns", "tcp", "kerberos", "ldap", "smb"}:
            score -= 1

    evidence_points = 0
    for count in (
        endpoint.get("conn_count", 0),
        len(matches_by_log),
        len(notice_matched),
        len(weird_matched),
        len(top_dns_queries),
        len(top_http_hosts),
        len(top_file_names),
    ):
        if count:
            evidence_points += 1

    summary_bits = [f"Cross-log Zeek profile for {ip}: {endpoint.get('conn_count', 0)} conn.log connections."]
    if endpoint.get("responded_count") or endpoint.get("initiated_count"):
        summary_bits.append(
            f"Role split: initiated {endpoint.get('initiated_count', 0)}, responded {endpoint.get('responded_count', 0)}."
        )
    if http_fallback_rows:
        matches_by_log["http.packet_fallback"] = {
            "count": len(http_fallback_rows),
            "preview": _rows_preview(http_fallback_rows, ["id.orig_h", "id.resp_h", "method", "host", "uri", "status_code", "resp_mime_types", "stream", "frames"], limit=10),
        }
    if file_fallback_rows:
        matches_by_log["files.packet_fallback"] = {
            "count": len(file_fallback_rows),
            "preview": _rows_preview(file_fallback_rows, ["id.orig_h", "id.resp_h", "filename", "mime_type", "host", "uri", "frames"], limit=10),
        }
    if ssl_fallback_rows and not ssl_matched:
        matches_by_log["ssl.packet_fallback"] = {
            "count": len(ssl_fallback_rows),
            "preview": _rows_preview(ssl_fallback_rows, ["id.orig_h", "id.resp_h", "server_name", "version", "cipher", "handshake_type", "frame"], limit=10),
        }
    if matches_by_log:
        summary_bits.append(
            "Other matching logs: " + ", ".join(f"{name} ({details['count']})" for name, details in sorted(matches_by_log.items())) + "."
        )
    if notice_types:
        summary_bits.append("Notices: " + ", ".join(f"{item['note']} ({item['count']})" for item in notice_types[:5]) + ".")
    if weird_types:
        summary_bits.append("Weirds: " + ", ".join(f"{item['name']} ({item['count']})" for item in weird_types[:5]) + ".")

    suspicion = _score_to_suspicion(score)
    confidence = _confidence_label(evidence_points)
    assessment_summary = (
        f"Score {score} with {confidence} confidence based on role split, cross-log coverage, and notable-vs-benign signals."
    )

    return {
        "ip": ip,
        "conn": endpoint,
        "matches_by_log": matches_by_log,
        "top_dns_queries": top_dns_queries,
        "top_http_hosts": top_http_hosts,
        "http_packet_fallback_rows": http_fallback_rows,
        "file_packet_fallback_rows": file_fallback_rows,
        "ssl_packet_fallback_rows": ssl_fallback_rows,
        "top_file_names": top_file_names,
        "notice_types": notice_types,
        "weird_types": weird_types,
        "dce_rpc_operations": dce_rpc_ops,
        "public_peer_count": len([peer for peer in public_peers if peer]),
        "suspicion": suspicion,
        "suspicion_score": score,
        "confidence": confidence,
        "suspicion_reasons": suspicion_reasons,
        "benign_signals": benign_signals,
        "assessment_summary": assessment_summary,
        "summary_text": " ".join(summary_bits),
    }


def safe_zeek_summary(pcap: str) -> dict[str, Any]:
    try:
        return zeek_summary(pcap)
    except Exception as exc:
        return {"ready": False, "error": str(exc), "logs": []}


def protocol_hierarchy(pcap: str, limit: int = 15) -> list[str]:
    pcap_path = resolve_pcap(pcap)
    proc = run_command(["tshark", "-r", str(pcap_path), "-q", "-z", "io,phs"])
    if proc.returncode != 0:
        return []
    lines: list[str] = []
    capture = False
    for raw_line in proc.stdout.splitlines():
        line = raw_line.rstrip()
        if "Protocol Hierarchy Statistics" in line:
            capture = True
            continue
        if not capture:
            continue
        if not line.strip() or line.strip().startswith("Filter:"):
            continue
        if set(line.strip()) <= {"=", "-"}:
            continue
        if "frames:" not in line and "bytes:" not in line:
            continue
        cleaned = re.sub(r"^\s+", "", line)
        cleaned = re.sub(r"\s+", " ", cleaned)
        lines.append(cleaned)
        if len(lines) >= limit:
            break
    return lines


def tshark_stat_block(pcap: str, stat: str, max_lines: int | None = 80) -> str:
    pcap_path = resolve_pcap(pcap)
    proc = run_command(["tshark", "-r", str(pcap_path), "-q", "-z", stat])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"tshark failed with {proc.returncode}")
    lines = proc.stdout.splitlines()
    if max_lines is not None and len(lines) > max_lines:
        lines = lines[:max_lines]
    return "\n".join(lines).strip()


def host_resolution_block(pcap: str, max_lines: int | None = 80) -> str:
    pcap_path = resolve_pcap(pcap)
    proc = run_command(["tshark", "-r", str(pcap_path), "-q", "-z", "hosts"])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"tshark failed with {proc.returncode}")
    lines = proc.stdout.splitlines()
    if max_lines is not None and len(lines) > max_lines:
        lines = lines[:max_lines]
    return "\n".join(lines).strip()


def endpoint_stat_rows(pcap: str) -> list[dict[str, Any]]:
    pcap_path = resolve_pcap(pcap)
    proc = run_command(["tshark", "-r", str(pcap_path), "-q", "-z", "endpoints,ip"])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"tshark failed with {proc.returncode}")
    rows: list[dict[str, Any]] = []
    for raw in proc.stdout.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("=") or line.startswith("Filter:") or line.startswith("IPv4 Endpoints"):
            continue
        if line.strip().startswith("|") or "Packets" in line and "Rx Bytes" in line:
            continue
        if not re.match(r"^\s*[0-9a-fA-F:.]+\s+\d+", line):
            continue
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 7:
            continue
        ip = parts[0]
        try:
            rows.append(
                {
                    "IP": ip,
                    "Packets": int(parts[1]),
                    "Bytes": int(parts[2]),
                    "Tx Packets": int(parts[3]),
                    "Tx Bytes": int(parts[4]),
                    "Rx Packets": int(parts[5]),
                    "Rx Bytes": int(parts[6]),
                }
            )
        except ValueError:
            continue
    return rows


def summary_rows(pcap: str, protocol: str | None = None, limit: int = DEFAULT_SUMMARY_LIMIT) -> list[dict[str, str]]:
    pcap_path = resolve_pcap(pcap)
    display_filter = protocol or "frame"
    command = [
        "tshark", "-r", str(pcap_path), "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-E", "header=y",
        "-E", "separator=\t",
        "-c", str(limit),
    ]
    proc = run_command(command)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"tshark failed with {proc.returncode}")
    return parse_tshark_table(proc.stdout)


def around_rows(pcap: str, frame: int, before: int = 20, after: int = 20) -> list[dict[str, str]]:
    pcap_path = resolve_pcap(pcap)
    start = max(1, frame - before)
    end = frame + after
    display_filter = f"frame.number >= {start} && frame.number <= {end}"
    command = [
        "tshark", "-r", str(pcap_path), "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-E", "header=y",
        "-E", "separator=\t",
    ]
    proc = run_command(command)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"tshark failed with {proc.returncode}")
    return parse_tshark_table(proc.stdout)


def endpoint_rows(pcap: str, ip: str, protocol: str | None = None, limit: int = 100) -> list[dict[str, str]]:
    pcap_path = resolve_pcap(pcap)
    endpoint_filter = f"ip.addr == {ip}"
    display_filter = endpoint_filter if not protocol else f"({endpoint_filter}) && ({protocol})"
    command = [
        "tshark", "-r", str(pcap_path), "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-E", "header=y",
        "-E", "separator=\t",
        "-c", str(limit),
    ]
    proc = run_command(command)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"tshark failed with {proc.returncode}")
    return parse_tshark_table(proc.stdout)


def pair_rows(pcap: str, src: str, dst: str, protocol: str | None = None, limit: int = 100) -> list[dict[str, str]]:
    pcap_path = resolve_pcap(pcap)
    pair_filter = f"ip.addr == {src} && ip.addr == {dst}"
    display_filter = pair_filter if not protocol else f"({pair_filter}) && ({protocol})"
    command = [
        "tshark", "-r", str(pcap_path), "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-E", "header=y",
        "-E", "separator=\t",
        "-c", str(limit),
    ]
    proc = run_command(command)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"tshark failed with {proc.returncode}")
    return parse_tshark_table(proc.stdout)


def export_frame_range(pcap: str, start: int, end: int, output: str | None = None) -> Path:
    pcap_path = resolve_pcap(pcap)
    out_name = output or f"{pcap_path.stem}-frames-{start}-{end}.pcapng"
    out_path = EXPORTS_DIR / out_name
    proc = run_command(["editcap", "-r", str(pcap_path), str(out_path), str(start), str(end)])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"editcap failed with {proc.returncode}")
    return out_path


def build_read_summary(pcap: str) -> dict[str, Any]:
    rows = safe_table_rows(lambda: summary_rows(pcap, limit=25))
    protocols = safe_lines(lambda: protocol_hierarchy(pcap, limit=12))
    return {
        "timeline_preview": rows,
        "top_protocols": protocols,
        "endpoints_preview": safe_text_block(lambda: tshark_stat_block(pcap, "endpoints,ip", max_lines=40), TSHARK_UNAVAILABLE_TEXT),
        "conversations_preview": safe_text_block(lambda: tshark_stat_block(pcap, "conv,ip", max_lines=40), TSHARK_UNAVAILABLE_TEXT),
        "hosts_preview": safe_text_block(lambda: host_resolution_block(pcap, max_lines=40), TSHARK_UNAVAILABLE_TEXT),
        "suggestions": [
            "Explore broadly",
            "Focus on a protocol such as http, dns, smb, kerberos, or modbus",
            "Jump to a frame like 'look at frame 1842'",
            "Inspect an IP pair like 'inspect 10.0.0.5 and 10.0.0.10'",
            "Export a reduced slice like 'export frames 800-920'",
        ],
    }


def ingest_pcap(pcap: str) -> dict[str, str]:
    ensure_dirs()
    pcap_path = resolve_pcap(pcap)
    proc = run_command(["capinfos", str(pcap_path)])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or f"capinfos failed with {proc.returncode}")
    text_path = OUTPUT_DIR / f"{pcap_path.name}.capinfos.txt"
    json_path = OUTPUT_DIR / f"{pcap_path.name}.metadata.json"
    read_summary = build_read_summary(str(pcap_path))
    metadata = {
        "pcap": str(pcap_path),
        "relative_path": pcap_relative_path(pcap_path),
        "artifact": str(text_path),
        "tool": "capinfos",
        "returncode": proc.returncode,
        "raw_stdout": proc.stdout,
        "parsed": parse_capinfos(proc.stdout),
        "read_summary": read_summary,
    }
    text_path.write_text(proc.stdout)
    write_json(json_path, metadata)
    set_current_pcap(str(pcap_path))
    return {"capinfos": str(text_path), "metadata_json": str(json_path)}


def metadata_for_pcap(pcap: str) -> dict[str, Any]:
    pcap_path = resolve_pcap(pcap)
    json_path = OUTPUT_DIR / f"{pcap_path.name}.metadata.json"
    if not json_path.exists():
        ingest_pcap(str(pcap_path))
    data = read_json(json_path)
    if not data:
        raise RuntimeError(f"Unable to parse metadata JSON: {json_path}")
    changed = False
    if data.get("relative_path") != pcap_relative_path(pcap_path):
        data["relative_path"] = pcap_relative_path(pcap_path)
        changed = True
    if "parsed" not in data and data.get("raw_stdout"):
        data["parsed"] = parse_capinfos(data["raw_stdout"])
        changed = True
    read_summary = data.get("read_summary")
    if "read_summary" not in data:
        data["read_summary"] = build_read_summary(str(pcap_path))
        changed = True
    elif tshark_available() and read_summary_is_degraded(read_summary):
        data["read_summary"] = build_read_summary(str(pcap_path))
        changed = True
    if changed:
        try:
            write_json(json_path, data)
        except PermissionError:
            pass
    return data


def latest_metadata() -> dict[str, Any] | None:
    current = current_pcap()
    if current:
        try:
            return metadata_for_pcap(current)
        except Exception:
            pass
    ensure_dirs()
    files = sorted(OUTPUT_DIR.glob("*.metadata.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return None
    try:
        return json.loads(files[0].read_text())
    except Exception:
        return {"artifact": str(files[0]), "error": "Unable to parse metadata JSON"}


def build_overview(pcap: str) -> dict[str, Any]:
    metadata = metadata_for_pcap(pcap)
    read_summary = metadata.get("read_summary", {})
    zeek = safe_zeek_summary(pcap)

    if tshark_available() and read_summary_is_degraded(read_summary):
        read_summary = build_read_summary(pcap)
        metadata["read_summary"] = read_summary
        try:
            pcap_path = resolve_pcap(pcap)
            write_json(OUTPUT_DIR / f"{pcap_path.name}.metadata.json", metadata)
        except PermissionError:
            pass

    endpoints_text = read_summary.get("endpoints_preview")
    if not endpoints_text:
        endpoints_text = tshark_stat_block(pcap, "endpoints,ip", max_lines=80)

    conversations_text = read_summary.get("conversations_preview")
    if not conversations_text:
        conversations_text = tshark_stat_block(pcap, "conv,ip", max_lines=80)

    hosts_text = read_summary.get("hosts_preview")
    if not hosts_text:
        hosts_text = host_resolution_block(pcap, max_lines=80)

    return {
        "pcap": metadata.get("relative_path") or pcap,
        "metadata": metadata,
        "capinfos_text": metadata.get("raw_stdout", ""),
        "timeline_preview": read_summary.get("timeline_preview", []),
        "event_timeline": zeek.get("event_timeline", []),
        "top_protocols": read_summary.get("top_protocols", []),
        "endpoints_text": endpoints_text,
        "conversations_text": conversations_text,
        "hosts_text": hosts_text,
        "endpoints_page": endpoint_page(pcap, page=1, page_size=25),
        "conversations_page": conversation_page(pcap, page=1, page_size=25) if zeek.get("ready") else None,
        "hosts_page": host_page(pcap, page=1, page_size=25) if zeek.get("ready") else None,
        "zeek_summary": zeek,
        "triage_sections": _zeek_triage_sections(metadata, zeek),
    }


def list_pcaps() -> list[dict[str, Any]]:
    ensure_dirs()
    results: list[dict[str, Any]] = []
    for path in sorted(INCOMING_DIR.rglob("*.pcap*")):
        if path.is_file():
            results.append(
                {
                    "name": path.name,
                    "relative_path": str(path.relative_to(INCOMING_DIR)),
                    "size_bytes": path.stat().st_size,
                }
            )
    return results
