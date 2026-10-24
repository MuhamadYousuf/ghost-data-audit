"""Shared normalization helpers for evidence format parsers."""

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from ..models import EvidenceFile, Observation


RESOURCE_ID_RE = re.compile(
    r"\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|"
    r"tombstone|marketing|object|legal_hold|cache|email_delivery)_\d+\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[A-F0-9]{64}\b", re.IGNORECASE)
USER_ID_RE = re.compile(r"\buser_\d+\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\w)\+\d(?:[\d\s()./-]*\d){6,14}(?!\w)")
PROPER_NAME_RE = re.compile(
    r"\b[A-Z][A-Za-z’'-]{1,}(?:\s+[A-Z][A-Za-z’'-]{1,}){1,3}\b"
)
TIMESTAMP_KEYS = (
    "observed_at",
    "recorded_at",
    "captured_at",
    "event_time",
    "timestamp",
    "time",
    "ts",
    "updated_at",
    "created_at",
)
IDENTITY_KEYS = frozenset(
    {
        "user_id",
        "user_ref",
        "subject_reference",
        "subject_ref",
        "customer_reference",
        "customer_ref",
        "customer_id",
        "owner_id",
        "actor_id",
        "lookup_key",
        "match_key",
        "scan_key",
        "correlation_key",
        "matched_value",
        "identifier",
        "subject_key",
        "owner_key",
    }
)
NAME_KEYS = frozenset(
    {
        "name",
        "full_name",
        "customer_name",
        "requester_name",
        "display_name",
        "first_name",
        "last_name",
        "owner_name",
        "actor_name",
    }
)


def parse_observation_time(value: Any) -> datetime | None:
    """Parse common ISO timestamps and normalize them to aware UTC datetimes."""

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def first_record_time(record: Mapping[str, Any]) -> datetime | None:
    by_lower = {str(key).casefold(): value for key, value in record.items()}
    for key in TIMESTAMP_KEYS:
        if key in by_lower:
            parsed = parse_observation_time(by_lower[key])
            if parsed is not None:
                return parsed
    return None


def scalar_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def attributes_from_record(record: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Keep each raw field, serializing nested values deterministically."""

    return tuple(sorted((str(key), scalar_text(value)) for key, value in record.items()))


def _iter_key_values(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            yield key_text, child
            yield from _iter_key_values(child)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for child in value:
            yield from _iter_key_values(child)


def normalize_identifier(value: str) -> str:
    text = value.strip()
    if EMAIL_RE.fullmatch(text) or HASH_RE.fullmatch(text):
        return text.lower()
    return text


def identifiers_from_record(record: Mapping[str, Any]) -> frozenset[str]:
    identifiers: set[str] = set()
    for key, value in _iter_key_values(record):
        if not isinstance(value, str) or not value:
            continue
        key_norm = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
        for match in EMAIL_RE.findall(value):
            identifiers.add(match.lower())
        for match in HASH_RE.findall(value):
            identifiers.add(match.lower())
        for match in USER_ID_RE.findall(value):
            identifiers.add(match)
        if (
            (key_norm in IDENTITY_KEYS or key_norm in NAME_KEYS or "phone" in key_norm)
            and value.strip().casefold() not in {"", "-", "none", "null", "n/a", "unknown"}
        ):
            identifiers.add(normalize_identifier(value))
    return frozenset(item for item in identifiers if item)


def identifiers_from_text(
    text: str, *, labeled_phone: bool = False, include_names: bool = False
) -> frozenset[str]:
    identifiers = {match.lower() for match in EMAIL_RE.findall(text)}
    identifiers.update(match.lower() for match in HASH_RE.findall(text))
    identifiers.update(USER_ID_RE.findall(text))
    identifiers.update(match.group(0) for match in PHONE_RE.finditer(text))
    if include_names:
        identifiers.update(PROPER_NAME_RE.findall(text))
    if labeled_phone:
        for line in text.splitlines():
            if re.search(r"\b(?:phone|mobile|telephone)\b", line, re.IGNORECASE):
                tail = re.split(r"[:=]", line, maxsplit=1)
                if len(tail) == 2 and tail[1].strip():
                    identifiers.add(tail[1].strip())
    return frozenset(item for item in identifiers if item)


def resource_ids_from_text(text: str) -> tuple[str, ...]:
    return tuple(sorted(set(RESOURCE_ID_RE.findall(text)), key=lambda item: (item.casefold(), item)))


def resource_ids_from_record(record: Mapping[str, Any], raw_text: str = "") -> tuple[str, ...]:
    resources: set[str] = set(resource_ids_from_text(raw_text)) if raw_text else set()
    for key, value in record.items():
        if str(key).casefold() in {"resource_id", "resourceid"} and isinstance(value, str) and value.strip():
            resources.add(value.strip())
        if isinstance(value, str):
            resources.update(resource_ids_from_text(value))
    return tuple(sorted(resources, key=lambda item: (item.casefold(), item)))


def infer_system_from_label(label: str) -> str:
    text = label.casefold()
    rules = (
        (("account", "profile", "tombstone", "identity"), "account_service"),
        (("search", "index", "cache"), "search_service"),
        (("analytics",), "analytics_platform"),
        (("support", "ticket", "attachment", "conversation"), "support_platform"),
        (("export", "manifest", "download"), "export_service"),
        (("integration", "connector", "subscription", "data_flow"), "integration_service"),
        (("backup", "restore", "archive"), "backup_service"),
        (("security", "audit", "legal_hold", "retained_order"), "security_service"),
        (("marketing", "email_delivery"), "marketing_platform"),
        (("object", "storage"), "object_storage"),
        (("legal",), "legal_service"),
    )
    for needles, system_id in rules:
        if any(needle in text for needle in needles):
            return system_id
    return ""


def system_id_from_record(
    record: Mapping[str, Any], *, container: str = "", inherited_system: str = ""
) -> str:
    by_lower = {str(key).casefold(): value for key, value in record.items()}
    for key in ("system_id", "system", "origin_system", "source_system", "service", "platform"):
        value = by_lower.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if inherited_system:
        return inherited_system
    for key in ("data_store", "collection", "collection_name", "table", "container"):
        value = by_lower.get(key)
        if isinstance(value, str):
            inferred = infer_system_from_label(value)
            if inferred:
                return inferred
    return infer_system_from_label(container)


def container_from_record(record: Mapping[str, Any], fallback: str = "") -> str:
    by_lower = {str(key).casefold(): value for key, value in record.items()}
    for key in ("container", "table", "table_name", "collection_name", "collection", "replica"):
        value = by_lower.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def record_type_from_record(record: Mapping[str, Any], *, label: str = "") -> str:
    by_lower = {str(key).casefold(): value for key, value in record.items()}
    for key in ("record_type", "entity_type", "data_category", "record_category", "type"):
        value = by_lower.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    merged = " ".join((label, *(str(key) for key in record))).casefold()
    if "tombstone" in merged or "deleted_customer_reference" in merged:
        return "ACCOUNT_TOMBSTONE"
    rules = (
        (("security", "audit_record", "legal_hold"), "SECURITY_AUDIT_LOG"),
        (("support", "ticket", "attachment", "conversation"), "SUPPORT_MESSAGE"),
        (("search", "index"), "SEARCH_INDEX_ENTRY"),
        (("analytics",), "ANALYTICS_PROFILE"),
        (("backup", "restore", "archive"), "BACKUP_ARCHIVE"),
        (("connector", "subscription", "data_flow", "integration"), "DATA_FLOW"),
        (("export", "manifest", "download"), "USER_EXPORT"),
        (("profile", "account", "identity"), "USER_PROFILE"),
    )
    for needles, record_type in rules:
        if any(needle in merged for needle in needles):
            return record_type
    return ""


def make_observations(
    record: Mapping[str, Any],
    *,
    evidence: EvidenceFile,
    container: str,
    locator: str,
    inherited_system: str = "",
    inherited_time: datetime | None = None,
    extra_identifiers: Iterable[str] = (),
    extra_attributes: Iterable[tuple[str, str]] = (),
    raw_text: str = "",
    emit_without_resource: bool = True,
) -> tuple[Observation, ...]:
    resources = resource_ids_from_record(record, raw_text)
    if not resources and emit_without_resource:
        resources = ("",)
    if not resources:
        return ()
    observed_at = first_record_time(record) or inherited_time or evidence.captured_at
    system_id = system_id_from_record(record, container=container, inherited_system=inherited_system)
    actual_container = container_from_record(record, container)
    record_type = record_type_from_record(record, label=actual_container or container)
    if not system_id and resources[0]:
        system_id = infer_system_from_label(resources[0])
    if not record_type and resources[0]:
        record_type = record_type_from_record({}, label=resources[0])
    identifiers = set(identifiers_from_record(record))
    identifiers.update(normalize_identifier(value) for value in extra_identifiers if value)
    attrs = dict(attributes_from_record(record))
    attrs.update((str(key), str(value)) for key, value in extra_attributes)
    sorted_attributes = tuple(sorted(attrs.items()))
    return tuple(
        Observation(
            file_id=evidence.file_id,
            file_captured_at=evidence.captured_at,
            observed_at=observed_at,
            system_id=system_id,
            resource_id=resource_id,
            record_type=record_type,
            container=actual_container,
            identifiers=frozenset(identifiers),
            attributes=sorted_attributes,
            locator=locator,
        )
        for resource_id in resources
    )
