"""Content-based evidence format detection and corpus aggregation."""

import re
from pathlib import Path

from ..loaders import load_evidence_files
from ..models import EvidenceCorpus, EvidenceFile, EvidenceFileSummary
from ..paths import DATASET_DIR
from .common import resource_ids_from_text
from .json_parser import parse_json
from .log_parser import parse_log
from .pdf_parser import parse_pdf
from .png_parser import parse_png
from .result import ParserOutput
from .sql_parser import parse_sql
from .text_parser import parse_generic_text, parse_handover_text, HANDOVER_RE


PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PDF_MAGIC = b"%PDF-"
SQL_STRUCTURE_RE = re.compile(r"\b(?:CREATE\s+TABLE|INSERT\s+INTO|CREATE\s+INDEX|PRAGMA)\b", re.IGNORECASE)
TIMESTAMP_JSON_RE = re.compile(r"^\s*\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d.*?\s+\{", re.MULTILINE)
RFC5424_RE = re.compile(r"^\s*(?:\d{4}-\d\d-\d\dT\S+\s+)?<\d+>\d\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+", re.MULTILINE)
KEY_VALUE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*=(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s]+)")


def detect_format(data: bytes) -> tuple[str, str | None]:
    """Detect evidence type from bytes/content, returning decoded text when applicable."""

    if data.startswith(PNG_MAGIC):
        return "PNG", None
    if data.startswith(PDF_MAGIC):
        return "PDF", None
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "UNKNOWN_BINARY", None
    stripped = text.lstrip()
    if not stripped:
        return "TEXT", text
    if stripped[:1] in ("{", "["):
        try:
            import json

            json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            return "JSON", text
    if SQL_STRUCTURE_RE.search(text):
        return "SQL", text
    if any(HANDOVER_RE.match(line) for line in text.splitlines()):
        return "TXT", text
    if TIMESTAMP_JSON_RE.search(text) or RFC5424_RE.search(text):
        return "LOG", text
    if any(len(KEY_VALUE_RE.findall(line)) >= 2 for line in text.splitlines()):
        return "LOG", text
    return "TEXT", text


def _fallback_resource_observations(
    output: ParserOutput, evidence: EvidenceFile, text: str
) -> None:
    seen = {item.resource_id for item in output.observations if item.resource_id}
    for line_number, line in enumerate(text.splitlines(), start=1):
        for resource_id in resource_ids_from_text(line):
            if resource_id in seen:
                continue
            observation = Observation(
                file_id=evidence.file_id,
                file_captured_at=evidence.captured_at,
                observed_at=evidence.captured_at,
                system_id="",
                resource_id=resource_id,
                record_type="",
                container="",
                identifiers=frozenset(),
                attributes=(),
                locator=f"{evidence.file_path}:{line_number}",
            )
            output.observations.append(observation)
            output.add_unrecognized(
                observation.locator,
                f"resource_id {resource_id} was retained by the generic text recall fallback",
            )
            seen.add(resource_id)


def parse_evidence_file(evidence: EvidenceFile, *, dataset_dir: str | Path = DATASET_DIR) -> EvidenceFileSummary:
    source = Path(dataset_dir) / evidence.file_path
    try:
        data = source.read_bytes()
    except OSError as exc:
        return EvidenceFileSummary(
            file_id=evidence.file_id,
            file_path=evidence.file_path,
            format="MISSING",
            observations=(),
            unrecognized=(f"{evidence.file_path}: evidence file could not be read ({type(exc).__name__})",),
        )

    file_format, text = detect_format(data)
    output: ParserOutput
    if file_format == "PNG":
        output = parse_png(evidence)
    elif file_format == "PDF":
        try:
            output = parse_pdf(data, evidence)
        except Exception as exc:  # Keep an inspection pass informative for damaged PDFs.
            output = ParserOutput()
            output.add_unrecognized(evidence.file_path, f"PDF extraction failed ({type(exc).__name__})")
    elif file_format == "SQL" and text is not None:
        output = parse_sql(text, evidence)
    elif file_format == "JSON" and text is not None:
        output = parse_json(text, evidence)
    elif file_format == "TXT" and text is not None:
        output = parse_handover_text(text, evidence)
    elif file_format == "LOG" and text is not None:
        output = parse_log(text, evidence)
    elif text is not None:
        output = parse_generic_text(text, evidence)
    else:
        output = ParserOutput()
        output.add_unrecognized(evidence.file_path, "unsupported binary evidence content")

    if text is not None:
        _fallback_resource_observations(output, evidence, text)

    return EvidenceFileSummary(
        file_id=evidence.file_id,
        file_path=evidence.file_path,
        format=file_format,
        observations=tuple(output.observations),
        unrecognized=tuple(sorted(output.unrecognized)),
        extracted_text=output.extracted_text,
    )


def parse_all_evidence(*, dataset_dir: str | Path = DATASET_DIR) -> EvidenceCorpus:
    """Parse every manifest item deterministically into a normalized observation corpus."""

    manifest_path = Path(dataset_dir) / "evidence_files.csv"
    manifest = load_evidence_files(manifest_path)
    summaries = tuple(
        parse_evidence_file(item, dataset_dir=dataset_dir)
        for item in sorted(manifest, key=lambda entry: (entry.file_id.casefold(), entry.file_id))
    )
    return EvidenceCorpus(summaries)
