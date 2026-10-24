"""Parser for the pipe-delimited handover text format and generic text fallbacks."""

import re

from ..models import EvidenceFile
from .common import (
    identifiers_from_text,
    make_observations,
    parse_observation_time,
    resource_ids_from_text,
)
from .result import ParserOutput


HANDOVER_RE = re.compile(
    r"^\s*-\s*(?P<observed>[^|]+?)\s*\|\s*(?P<system>[^|]+?)\s*\|\s*"
    r"(?P<resource>[^|]+?)\s*\|\s*(?P<record_type>[^|]+?)\s*\|\s*"
    r"(?P<state>[^|]+?)\s*\|\s*(?P<identifier>.*?)\s*$"
)


def parse_handover_text(text: str, evidence: EvidenceFile) -> ParserOutput:
    result = ParserOutput()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        locator = f"{evidence.file_path}:{line_number}"
        match = HANDOVER_RE.match(line)
        if match:
            fields = match.groupdict()
            record = {
                "resource_id": fields["resource"].strip(),
                "system_id": fields["system"].strip(),
                "record_type": fields["record_type"].strip(),
                "state": fields["state"].strip(),
                "identifier": fields["identifier"].strip(),
            }
            observed_at = parse_observation_time(fields["observed"])
            if observed_at is not None:
                record["observed_at"] = fields["observed"].strip()
            result.observations.extend(
                make_observations(
                    record,
                    evidence=evidence,
                    container="handover",
                    locator=locator,
                    extra_identifiers=identifiers_from_text(fields["identifier"], labeled_phone=True),
                )
            )
            continue

        resources = resource_ids_from_text(line)
        identifiers = identifiers_from_text(line, labeled_phone=True)
        if resources or identifiers:
            for resource_id in resources or ("",):
                record = {"resource_id": resource_id, "line_text": line}
                result.observations.extend(
                    make_observations(
                        record,
                        evidence=evidence,
                        container="text_record",
                        locator=locator,
                        extra_identifiers=identifiers,
                    )
                )
            result.add_unrecognized(locator, "text line did not match the handover record structure")
        else:
            result.add_unrecognized(locator, "ignored non-record text line (header or decoration)")
    return result


def parse_generic_text(text: str, evidence: EvidenceFile) -> ParserOutput:
    """Retain resource and contact tokens from text whose structure is unknown."""

    result = ParserOutput()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        locator = f"{evidence.file_path}:{line_number}"
        resources = resource_ids_from_text(line)
        identifiers = identifiers_from_text(line, labeled_phone=True)
        if resources or identifiers:
            for resource_id in resources or ("",):
                result.observations.extend(
                    make_observations(
                        {"resource_id": resource_id, "line_text": line},
                        evidence=evidence,
                        container="text_record",
                        locator=locator,
                        extra_identifiers=identifiers,
                    )
                )
        else:
            result.add_unrecognized(locator, "ignored unstructured line with no resource_id or identity token")
    return result
