"""Parser for key/value, timestamped JSON, and RFC5424-style service logs."""

import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from ..models import EvidenceFile
from .common import (
    first_record_time,
    identifiers_from_record,
    identifiers_from_text,
    make_observations,
    parse_observation_time,
    resource_ids_from_record,
)
from .result import ParserOutput


TIMESTAMP_PREFIX_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(.*)$"
)
KV_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.-]*)=(?:\"((?:\\.|[^\"])*)\"|'((?:\\.|[^'])*)'|([^\s]+))"
)
RFC5424_RE = re.compile(r"^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$")
START_KEY_FIELDS = ("lookup_key", "match_key", "scan_key")
INFRASTRUCTURE_EVENTS = frozenset(
    {
        "dns_cache",
        "feature_flags",
        "consumer_lag",
        "connection_acquired",
        "cache_lookup",
        "slow_call_rate",
        "batch_started",
        "dependency_retry",
        "dependency_recovered",
        "timer_tick",
        "certificate_checked",
        "disk_latency",
        "secret_agent",
        "log_router",
        "webhook_delivery",
        "lambda_extension",
        "thumbnail_failed",
        "checkpoint_saved",
        "lease_extended",
    }
)


def _unquote(value: str, quote: str) -> str:
    if quote == '"':
        return value.replace('\\"', '"').replace('\\\\', '\\')
    return value.replace("\\'", "'").replace('\\\\', '\\')


def _key_value_fields(text: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for match in KV_RE.finditer(text):
        key, double_quoted, single_quoted, unquoted = match.groups()
        if double_quoted is not None:
            value = _unquote(double_quoted, '"')
        elif single_quoted is not None:
            value = _unquote(single_quoted, "'")
        else:
            value = unquoted or ""
        fields[key] = value
    return fields


def _decode_line(line: str) -> tuple[dict[str, Any], datetime | None, bool]:
    """Return parsed fields, the line timestamp, and whether RFC5424 framing was seen."""

    content = line.strip()
    timestamp: datetime | None = None
    prefix = TIMESTAMP_PREFIX_RE.match(content)
    if prefix:
        timestamp = parse_observation_time(prefix.group(1))
        content = prefix.group(2).strip()

    rfc_match = RFC5424_RE.match(content)
    is_rfc5424 = rfc_match is not None
    if rfc_match:
        _priority, _version, host, app, procid, msgid, structured_data, message = rfc_match.groups()
        fields: dict[str, Any] = _key_value_fields(message)
        fields.setdefault("_syslog_host", host)
        fields.setdefault("_syslog_app", app)
        fields.setdefault("_syslog_procid", procid)
        fields.setdefault("_syslog_msgid", msgid)
        if structured_data not in ("", "-"):
            fields.setdefault("_syslog_structured_data", structured_data)
        fields.setdefault("service", app)
        if procid.startswith("tr-"):
            fields.setdefault("trace_id", procid)
    elif content.startswith("{"):
        try:
            decoded = json.loads(content)
        except json.JSONDecodeError:
            fields = _key_value_fields(content)
        else:
            fields = decoded if isinstance(decoded, dict) else {"_json_value": decoded}
    else:
        fields = _key_value_fields(content)

    if timestamp is not None:
        fields.setdefault("observed_at", timestamp.isoformat().replace("+00:00", "Z"))
    return fields, timestamp, is_rfc5424


def _event_name(record: dict[str, Any]) -> str:
    for key in ("event", "event_type", "function", "operation", "message"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().casefold()
    return ""


def _trace_id(record: dict[str, Any]) -> str:
    value = record.get("trace_id")
    return value.strip() if isinstance(value, str) else ""


def _is_infrastructure_event(event: str, record: dict[str, Any]) -> bool:
    lowered = event.casefold()
    if lowered in INFRASTRUCTURE_EVENTS:
        return True
    for value in (record.get("service"), record.get("logger"), record.get("function")):
        if isinstance(value, str) and value.casefold() in INFRASTRUCTURE_EVENTS:
            return True
    return False


def parse_log(text: str, evidence: EvidenceFile) -> ParserOutput:
    result = ParserOutput()
    parsed_lines: list[tuple[int, str, dict[str, Any], datetime | None, bool]] = []
    joins: dict[str, list[tuple[str, str, int]]] = defaultdict(list)

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        fields, line_time, _is_rfc5424 = _decode_line(line)
        if not fields:
            result.add_unrecognized(f"{evidence.file_path}:{line_number}", "line has no parsed key/value fields")
            continue
        trace = _trace_id(fields)
        event = _event_name(fields)
        if trace and event.endswith("_started"):
            for key in START_KEY_FIELDS:
                value = fields.get(key)
                if isinstance(value, str) and value.strip():
                    joins[trace].append((key, value.strip(), line_number))
        parsed_lines.append((line_number, line, fields, line_time, bool(trace and event.endswith("_started"))))

    resource_traces = {
        _trace_id(fields)
        for _line_number, line, fields, _line_time, _is_join_start in parsed_lines
        if _trace_id(fields) and resource_ids_from_record(fields, line)
    }

    for line_number, line, fields, line_time, is_join_start in parsed_lines:
        resources = resource_ids_from_record(fields, line)
        identifiers = identifiers_from_record(fields) | identifiers_from_text(line)
        if not resources and is_join_start:
            # This line contributes a lookup key to its matching resource-bearing trace event.
            trace = _trace_id(fields)
            if trace and trace not in resource_traces:
                result.add_unrecognized(
                    f"{evidence.file_path}:{line_number}",
                    "unmatched lookup-start line has no resource-bearing trace event",
                )
            continue

        trace = _trace_id(fields)
        joined_values = joins.get(trace, ()) if trace else ()
        extra_ids = [value for _key, value, _source_line in joined_values]
        extra_attributes: list[tuple[str, str]] = []
        for key, value, source_line in joined_values:
            extra_attributes.append((f"joined_{key}", value))
            extra_attributes.append((f"joined_{key}_source_line", str(source_line)))

        locator = f"{evidence.file_path}:{line_number}"
        if resources or identifiers:
            if line_time is not None:
                fields.setdefault("observed_at", line_time.isoformat().replace("+00:00", "Z"))
            result.observations.extend(
                make_observations(
                    fields,
                    evidence=evidence,
                    container=str(fields.get("container") or fields.get("collection") or ""),
                    locator=locator,
                    extra_identifiers=extra_ids,
                    extra_attributes=extra_attributes,
                    raw_text=line,
                )
            )
        else:
            event = _event_name(fields)
            if _is_infrastructure_event(event, fields):
                result.add_unrecognized(locator, f"ignored infrastructure noise ({event or 'unspecified event'})")
            else:
                result.add_unrecognized(
                    locator,
                    "ignored resource-free log line (no resource_id or identity-bearing values)",
                )

    return result
