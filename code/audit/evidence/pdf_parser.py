"""Text extraction parser for PDF evidence using the pinned pypdf dependency."""

from datetime import datetime, timezone
from io import BytesIO
import re

from pypdf import PdfReader

from ..models import EvidenceFile
from .common import (
    identifiers_from_text,
    make_observations,
    parse_observation_time,
    resource_ids_from_text,
)
from .result import ParserOutput


ISO_TIME_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)
HUMAN_TIME_RE = re.compile(
    r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:UTC|GMT)?)?\b",
    re.IGNORECASE,
)


def _page_time(text: str) -> datetime | None:
    for match in ISO_TIME_RE.finditer(text):
        parsed = parse_observation_time(match.group(0))
        if parsed is not None:
            return parsed
    for match in HUMAN_TIME_RE.finditer(text):
        value = match.group(0).strip()
        for date_format in ("%d %b %Y %H:%M:%S %Z", "%d %b %Y %H:%M %Z", "%d %b %Y", "%d %B %Y"):
            try:
                parsed = datetime.strptime(value, date_format)
            except ValueError:
                continue
            return parsed.replace(tzinfo=timezone.utc)
    return None


def parse_pdf(data: bytes, evidence: EvidenceFile) -> ParserOutput:
    result = ParserOutput()
    reader = PdfReader(BytesIO(data))
    page_texts: list[str] = []
    for page_number, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        page_texts.append(text)
        resources = resource_ids_from_text(text)
        identifiers = identifiers_from_text(text, labeled_phone=True, include_names=True)
        if resources or identifiers:
            record = {"observed_at": (_page_time(text) or evidence.captured_at).isoformat()}
            result.observations.extend(
                make_observations(
                    record,
                    evidence=evidence,
                    container=f"pdf_page_{page_number}",
                    locator=f"{evidence.file_path}:page:{page_number}",
                    extra_identifiers=identifiers,
                    raw_text=text,
                )
            )
        elif text.strip():
            result.add_unrecognized(
                f"{evidence.file_path}:page:{page_number}",
                "ignored PDF page with no regex-recognized resource or identifier",
            )
    result.extracted_text = "\n".join(page_texts)
    return result
