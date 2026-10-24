"""Text extraction parser for PDF evidence using the pinned pypdf dependency."""

from io import BytesIO
import re

from pypdf import PdfReader

from ..models import EvidenceFile
from .common import (
    identifiers_from_text,
    make_observations,
    names_from_pdf_text,
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


def _document_dates(text: str) -> tuple[str, ...]:
    matches = [
        (match.start(), match.group(0).strip())
        for pattern in (ISO_TIME_RE, HUMAN_TIME_RE)
        for match in pattern.finditer(text)
    ]
    ordered: list[str] = []
    seen: set[str] = set()
    for _, value in sorted(matches):
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return tuple(ordered)


def parse_pdf(data: bytes, evidence: EvidenceFile) -> ParserOutput:
    result = ParserOutput()
    reader = PdfReader(BytesIO(data))
    page_texts: list[str] = []
    for page_number, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        page_texts.append(text)
        resources = resource_ids_from_text(text)
        identifiers = identifiers_from_text(text, labeled_phone=True)
        customer_names = names_from_pdf_text(text)
        if resources or identifiers or customer_names:
            record = {"document_dates": "; ".join(_document_dates(text))}
            if customer_names:
                record["customer_name"] = sorted(customer_names)[0]
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
