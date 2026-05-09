from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

import typer

from pire.core import (
    ZEEK_LOG_DIR,
    around_rows,
    ensure_dirs,
    export_frame_range,
    ingest_pcap,
    pair_rows,
    resolve_pcap,
    resolve_binary,
    run_command,
    summary_rows,
    zeek_available,
)
from pire.runtime import (
    add_api_questions,
    bootstrap_case,
    case_snapshot,
    ensure_runtime_structure,
    retrieve_layered_knowledge,
    save_api_answer,
    select_api_question,
)

app = typer.Typer(help="PIRE - PCAP Ingest, Read & Evaluate")


@app.callback()
def main() -> None:
    ensure_dirs()


@app.command()
def doctor() -> None:
    """Check whether required external binaries are available."""
    binaries = ["tshark", "capinfos", "editcap", "mergecap", "tcpdump", "zeek", "zeek-cut", "zkg", "jq", "yq", "rg"]
    results: dict[str, dict[str, Optional[str] | bool]] = {}
    for binary in binaries:
        path = resolve_binary(binary) or shutil.which(binary)
        results[binary] = {"available": path is not None, "path": path}
    results["zeek_runtime"] = {"available": zeek_available(), "log_dir": str(ZEEK_LOG_DIR)}
    typer.echo(json.dumps(results, indent=2))


@app.command()
def ingest(pcap: str) -> None:
    """Collect lightweight metadata for a PCAP."""
    try:
        result = ingest_pcap(pcap)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc))
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps(result, indent=2))


@app.command()
def summary(pcap: str, protocol: Optional[str] = typer.Option(None, "--protocol", "-p")) -> None:
    """Print a small first-pass packet/protocol summary."""
    try:
        rows = summary_rows(pcap, protocol=protocol)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc))
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    if not rows:
        typer.echo("No matching packets found.")
        return
    header = list(rows[0].keys())
    typer.echo("\t".join(header))
    for row in rows:
        typer.echo("\t".join(row.get(col, "") for col in header))


@app.command()
def pair(
    pcap: str,
    src: str = typer.Option(..., "--src"),
    dst: str = typer.Option(..., "--dst"),
    protocol: Optional[str] = typer.Option(None, "--protocol", "-p"),
    limit: int = typer.Option(100, "--limit"),
) -> None:
    """Show traffic between two IPs, optionally scoped by protocol/display filter."""
    try:
        rows = pair_rows(pcap, src=src, dst=dst, protocol=protocol, limit=limit)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc))
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    if not rows:
        typer.echo("No matching packets found.")
        return
    header = list(rows[0].keys())
    typer.echo("\t".join(header))
    for row in rows:
        typer.echo("\t".join(row.get(col, "") for col in header))


@app.command()
def around(
    pcap: str,
    frame: int = typer.Option(..., "--frame"),
    before: int = typer.Option(20, "--before"),
    after: int = typer.Option(20, "--after"),
) -> None:
    """Show packets around a frame number."""
    try:
        rows = around_rows(pcap, frame=frame, before=before, after=after)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc))
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    if not rows:
        typer.echo("No matching packets found.")
        return
    header = list(rows[0].keys())
    typer.echo("\t".join(header))
    for row in rows:
        typer.echo("\t".join(row.get(col, "") for col in header))


@app.command()
def export_frames(
    pcap: str,
    start: int = typer.Option(..., "--start"),
    end: int = typer.Option(..., "--end"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    """Export a frame range to a new PCAP using editcap."""
    try:
        out_path = export_frame_range(pcap, start=start, end=end, output=output)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc))
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1)
    typer.echo(str(out_path))


@app.command("init-runtime")
def init_runtime() -> None:
    """Create the runtime-facing PIRE library structure."""
    runtime_paths = ensure_runtime_structure()
    typer.echo(runtime_paths.model_dump_json(indent=2))


@app.command("init-case")
def init_case(
    case_id: str,
    focus: Optional[str] = typer.Option(None, "--focus"),
    summary: Optional[str] = typer.Option(None, "--summary"),
) -> None:
    """Create a starter runtime case directory and registry entry."""
    try:
        result = bootstrap_case(case_id, focus=focus, summary=summary)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    typer.echo(json.dumps(result, indent=2))


@app.command("case-show")
def case_show(case_id: str) -> None:
    """Show a runtime case snapshot."""
    try:
        result = case_snapshot(case_id)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    typer.echo(json.dumps(result, indent=2))


@app.command("retrieve")
def retrieve(topic: str, case_id: str = typer.Option(..., "--case-id")) -> None:
    """Retrieve protocol, experiential, and current-case notes for a topic."""
    try:
        result = retrieve_layered_knowledge(case_id, topic)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    typer.echo(json.dumps(result, indent=2))


@app.command("question-add")
def question_add(
    case_id: str = typer.Option(..., "--case-id"),
    question: str = typer.Option(..., "--question"),
    why_ask: Optional[str] = typer.Option(None, "--why-ask"),
    pcap_evidence: Optional[str] = typer.Option(None, "--pcap-evidence"),
    experiential_knowledge: Optional[str] = typer.Option(None, "--experiential-knowledge"),
    protocol_knowledge: Optional[str] = typer.Option(None, "--protocol-knowledge"),
    helpful_answer_would: Optional[str] = typer.Option(None, "--helpful-answer-would"),
) -> None:
    """Add a persisted candidate API question to a case."""
    result = add_api_questions(case_id, [{
        "question": question,
        "why_ask": why_ask,
        "pcap_evidence": pcap_evidence,
        "experiential_knowledge": experiential_knowledge,
        "protocol_knowledge": protocol_knowledge,
        "helpful_answer_would": helpful_answer_would,
    }])
    typer.echo(json.dumps(result, indent=2))


@app.command("question-select")
def question_select(case_id: str = typer.Option(..., "--case-id"), question_id: str = typer.Option(..., "--question-id")) -> None:
    """Mark an API question as selected/asked."""
    try:
        result = select_api_question(case_id, question_id)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    typer.echo(json.dumps(result, indent=2))


@app.command("question-answer")
def question_answer(
    case_id: str = typer.Option(..., "--case-id"),
    question_id: str = typer.Option(..., "--question-id"),
    answer_summary: str = typer.Option(..., "--answer-summary"),
    answer_body: Optional[str] = typer.Option(None, "--answer-body"),
) -> None:
    """Persist an answer for a previously added API question."""
    try:
        result = save_api_answer(case_id, question_id, answer_summary=answer_summary, answer_body=answer_body)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    typer.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
