"""PNG registration only; image pixels are intentionally not processed in Milestone 2."""

from ..models import EvidenceFile, Observation
from .result import ParserOutput


def parse_png(evidence: EvidenceFile) -> ParserOutput:
    result = ParserOutput()
    result.observations.append(
        Observation(
            file_id=evidence.file_id,
            file_captured_at=evidence.captured_at,
            observed_at=evidence.captured_at,
            system_id="",
            resource_id="",
            record_type="UNPARSED_MEDIA",
            container="image/png",
            identifiers=frozenset(),
            attributes=(("media_status", "unparsed"),),
            locator=f"{evidence.file_path}:media",
        )
    )
    return result
