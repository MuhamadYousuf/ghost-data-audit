"""Parser for structured JSON evidence, including nested service and snapshot exports."""

import json
from pathlib import PurePosixPath
from typing import Any

from ..models import EvidenceFile
from .common import (
    first_record_time,
    identifiers_from_record,
    make_observations,
    resource_ids_from_record,
    system_id_from_record,
)
from .result import ParserOutput


RECORD_ARRAY_KEYS = frozenset(
    {
        "records",
        "profiles",
        "profile_lookups",
        "restore_entries",
        "exports",
        "connectors",
        "index_queries",
        "audit_records",
        "tickets",
        "documents",
        "queries",
        "messages",
        "entries",
    }
)


def _child_pointer(parent: str, key: str | int) -> str:
    escaped = str(key).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}"


def parse_json(text: str, evidence: EvidenceFile) -> ParserOutput:
    result = ParserOutput()
    try:
        root: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        result.add_unrecognized(f"{evidence.file_path}:{exc.lineno}", "invalid JSON document")
        return result

    def visit(
        value: Any,
        pointer: str,
        *,
        parent_key: str = "",
        inherited_system: str = "",
        inherited_time=None,
        inherited_container: str = "",
        record_candidate: bool = False,
    ) -> None:
        if isinstance(value, list):
            is_record_list = parent_key.casefold() in RECORD_ARRAY_KEYS
            for index, child in enumerate(value):
                visit(
                    child,
                    _child_pointer(pointer, index),
                    parent_key=parent_key,
                    inherited_system=inherited_system,
                    inherited_time=inherited_time,
                    inherited_container=inherited_container,
                    record_candidate=is_record_list and isinstance(child, dict),
                )
            return

        if not isinstance(value, dict):
            return

        own_time = first_record_time(value) or inherited_time
        own_container = ""
        for field_name in ("container", "table", "table_name", "collection_name", "collection", "replica"):
            field_value = value.get(field_name)
            if isinstance(field_value, str) and field_value.strip():
                own_container = field_value.strip()
                break
        active_container = own_container or inherited_container
        active_system = system_id_from_record(
            value,
            container=active_container,
            inherited_system=inherited_system,
        )

        own_resources = resource_ids_from_record(value)
        is_record = record_candidate or bool(own_resources)
        if is_record:
            observations = make_observations(
                value,
                evidence=evidence,
                container=active_container,
                locator=f"{evidence.file_path}#{pointer or '/'}",
                inherited_system=active_system,
                inherited_time=own_time,
            )
            result.observations.extend(observations)
            if not own_resources and not identifiers_from_record(value):
                result.add_unrecognized(
                    f"{evidence.file_path}#{pointer or '/'}",
                    "structured record has no resource_id or recognized identifier fields",
                )

        for key, child in value.items():
            child_key = str(key)
            child_container = active_container
            child_system = active_system
            if parent_key.casefold() == "service_exports":
                child_system = child_key
                if not child_container:
                    child_container = child_key
            if child_key.casefold() in {"service_exports", "snapshots"}:
                # These are structural wrappers. Their children carry the useful context.
                pass
            elif (
                child_key.casefold() in RECORD_ARRAY_KEYS
                and (not child_container or child_container.casefold() == inherited_system.casefold())
            ):
                child_container = child_key
            visit(
                child,
                _child_pointer(pointer, child_key),
                parent_key=child_key,
                inherited_system=child_system,
                inherited_time=own_time,
                inherited_container=child_container,
            )

    visit(root, "")
    return result
