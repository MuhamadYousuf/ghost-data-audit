"""Validation of prediction CSV files against the project output contract."""

import csv
import io
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .contract import (
    ALLOWED_STEP_TRIPLES,
    DELETION_STATUSES,
    OPERATION_ORDER,
    OUTPUT_HEADER,
    PHASE_ORDER,
    STEP_FIELDS,
)
from .loaders import load_activities, load_audit_log, load_deletion_requests, load_evidence_files
from .models import DeletionRequest
from .paths import DATASET_DIR


def case_id_sort_key(case_id: str) -> tuple[tuple[tuple[int, int | str], ...], str]:
    """Sort identifiers naturally so case_33 precedes case_100."""

    parts = re.split(r"(\d+)", case_id)
    natural = tuple((1, int(part)) if part.isdigit() else (0, part.casefold()) for part in parts)
    return natural, case_id


def _context(case_id: str, step_no: int | str = "-") -> str:
    return f"case_id={case_id} step_no={step_no}: "


def _reference_context(dataset_dir: Path) -> tuple[set[str], dict[str, list[datetime]]]:
    evidence = load_evidence_files(dataset_dir / "evidence_files.csv")
    activities = load_activities(dataset_dir / "system_activity.csv")
    audit_entries = load_audit_log(dataset_dir / "user_audit_log.csv")
    valid_ids: set[str] = set()
    timestamps: dict[str, list[datetime]] = {}
    for item, identifier, timestamp in (
        *((record, record.file_id, record.captured_at) for record in evidence),
        *((record, record.activity_id, record.event_time) for record in activities),
        *((record, record.audit_id, record.event_time) for record in audit_entries),
    ):
        del item
        valid_ids.add(identifier)
        timestamps.setdefault(identifier, []).append(timestamp)
    return valid_ids, timestamps


def _sort_key(step: dict[str, object]) -> tuple[int, int, str, str]:
    phase = step.get("phase")
    operation = step.get("operation")
    phase_rank = PHASE_ORDER.get(phase, len(PHASE_ORDER)) if isinstance(phase, str) else len(PHASE_ORDER)
    if isinstance(phase, str) and isinstance(operation, str):
        operations = OPERATION_ORDER.get(phase, ())
        try:
            operation_rank = operations.index(operation)
        except ValueError:
            operation_rank = len(operations)
    else:
        operation_rank = 0
    system_id = step.get("system_id")
    resource_id = step.get("resource_id")
    return (
        phase_rank,
        operation_rank,
        system_id if isinstance(system_id, str) else "",
        resource_id if isinstance(resource_id, str) else "",
    )


def _expected_requests(path: str | Path | None) -> list[DeletionRequest] | None:
    if path is None:
        return None
    return load_deletion_requests(path)


def validate_output_text(
    content: str,
    *,
    expect_requests_path: str | Path | None = None,
    dataset_dir: str | Path = DATASET_DIR,
    check_evidence_time: bool = True,
) -> list[str]:
    """Return all detectable contract violations in CSV text held in memory."""

    errors: list[str] = []
    try:
        rows = list(csv.reader(io.StringIO(content, newline="")))
    except csv.Error as exc:
        return [_context("<csv>") + f"malformed CSV: {exc}"]

    if not rows:
        return [_context("<header>") + "file is empty; expected the exact output header"]

    header = rows[0]
    if tuple(header) != OUTPUT_HEADER:
        errors.append(
            _context("<header>")
            + f"header must be exactly {','.join(OUTPUT_HEADER)!r}; found {','.join(header)!r}"
        )

    expected: list[DeletionRequest] | None = None
    try:
        expected = _expected_requests(expect_requests_path)
    except (OSError, ValueError) as exc:
        errors.append(_context("<requests>") + f"could not load expected requests: {exc}")

    try:
        valid_evidence_ids, evidence_times = _reference_context(Path(dataset_dir))
    except (OSError, ValueError) as exc:
        errors.append(_context("<evidence-index>") + f"could not load evidence reference tables: {exc}")
        valid_evidence_ids, evidence_times = set(), {}

    request_by_id = {request.case_id: request for request in expected or []}
    seen_rows: dict[str, int] = {}
    case_ids: list[str] = []
    parsed_by_row: list[tuple[str, str, list[object] | None, int]] = []

    for line_number, row in enumerate(rows[1:], start=2):
        case_id = row[0] if row and row[0] else f"<row {line_number}>"
        if len(row) != len(OUTPUT_HEADER):
            errors.append(
                _context(case_id)
                + f"CSV row {line_number} must have exactly {len(OUTPUT_HEADER)} columns; found {len(row)}"
            )
        if not row:
            errors.append(_context(case_id) + f"CSV row {line_number} is blank")
            continue
        if len(row) < len(OUTPUT_HEADER):
            row = row + [""] * (len(OUTPUT_HEADER) - len(row))
        case_id, deletion_status, steps_json = row[:3]
        case_ids.append(case_id)
        if case_id in seen_rows:
            errors.append(
                _context(case_id)
                + f"duplicate case_id; first appeared on CSV row {seen_rows[case_id]}"
            )
        else:
            seen_rows[case_id] = line_number

        if deletion_status not in DELETION_STATUSES:
            errors.append(_context(case_id) + f"invalid deletion_status {deletion_status!r}")

        try:
            parsed_steps = json.loads(steps_json)
        except json.JSONDecodeError as exc:
            errors.append(
                _context(case_id)
                + f"steps_json is not valid JSON (CSV row {line_number}, column 3): {exc.msg}"
            )
            parsed_by_row.append((case_id, deletion_status, None, line_number))
            continue
        if not isinstance(parsed_steps, list):
            errors.append(_context(case_id) + "steps_json must parse to a JSON array")
            parsed_by_row.append((case_id, deletion_status, None, line_number))
            continue
        parsed_by_row.append((case_id, deletion_status, parsed_steps, line_number))

    for index in range(1, len(case_ids)):
        previous, current = case_ids[index - 1], case_ids[index]
        if case_id_sort_key(previous) > case_id_sort_key(current):
            errors.append(
                _context(current)
                + f"CSV row order is not numeric: {previous!r} appears before {current!r}"
            )

    if expected is not None:
        expected_ids = [request.case_id for request in expected]
        expected_counts: dict[str, int] = {}
        for case_id in expected_ids:
            expected_counts[case_id] = expected_counts.get(case_id, 0) + 1
        expected_set = set(expected_ids)
        actual_counts: dict[str, int] = {}
        for case_id in case_ids:
            actual_counts[case_id] = actual_counts.get(case_id, 0) + 1
        for case_id in expected_ids:
            if actual_counts.get(case_id, 0) == 0:
                errors.append(_context(case_id) + "missing required case_id from expected requests")
        for case_id in case_ids:
            if case_id not in expected_set:
                errors.append(_context(case_id) + "case_id is not present in expected requests")
        for case_id, count in expected_counts.items():
            if count > 1:
                errors.append(_context(case_id) + "expected requests file contains a duplicate case_id")
        if case_ids != expected_ids:
            for position in range(max(len(case_ids), len(expected_ids))):
                actual_id = case_ids[position] if position < len(case_ids) else "<missing row>"
                expected_id = expected_ids[position] if position < len(expected_ids) else "<no expected row>"
                if actual_id != expected_id:
                    errors.append(
                        _context(actual_id)
                        + f"row position {position + 1} does not match expected requests order ({expected_id!r})"
                    )

    for case_id, deletion_status, steps, _line_number in parsed_by_row:
        if steps is None:
            continue
        if deletion_status == "NOT_APPLICABLE" and steps != []:
            errors.append(_context(case_id) + "NOT_APPLICABLE requires an empty steps_json array")

        prior_key: tuple[int, int, str, str] | None = None
        for position, item in enumerate(steps, start=1):
            step_no = position
            if not isinstance(item, dict):
                errors.append(_context(case_id, step_no) + "step must be a JSON object")
                continue

            actual_fields = set(item)
            if actual_fields != STEP_FIELDS:
                missing = sorted(STEP_FIELDS - actual_fields)
                extra = sorted(actual_fields - STEP_FIELDS)
                details = []
                if missing:
                    details.append("missing " + ", ".join(missing))
                if extra:
                    details.append("unexpected " + ", ".join(extra))
                errors.append(_context(case_id, step_no) + "step must have exactly seven fields (" + "; ".join(details) + ")")

            supplied_step_no = item.get("step_no")
            if isinstance(supplied_step_no, bool) or not isinstance(supplied_step_no, int):
                errors.append(_context(case_id, step_no) + f"step_no must be an integer; found {supplied_step_no!r}")
            elif supplied_step_no != position:
                errors.append(
                    _context(case_id, supplied_step_no)
                    + f"step_no must be consecutive from 1; expected {position}"
                )

            for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                if field in item and not isinstance(item[field], str):
                    errors.append(_context(case_id, step_no) + f"{field} must be a string")

            phase, operation, state = item.get("phase"), item.get("operation"), item.get("state")
            triple_is_valid = (
                isinstance(phase, str)
                and isinstance(operation, str)
                and isinstance(state, str)
                and (phase, operation, state) in ALLOWED_STEP_TRIPLES
            )
            if not triple_is_valid:
                errors.append(
                    _context(case_id, step_no)
                    + f"invalid (phase, operation, state) triple {(phase, operation, state)!r}"
                )

            if not isinstance(phase, str) or phase not in PHASE_ORDER:
                errors.append(_context(case_id, step_no) + f"invalid phase {phase!r}")

            key = _sort_key(item)
            if prior_key is not None and key < prior_key:
                errors.append(
                    _context(case_id, step_no)
                    + "steps are out of order; expected phase, operation, system_id, resource_id order"
                )
            prior_key = key

            evidence_id = item.get("evidence_id")
            if isinstance(evidence_id, str) and evidence_id:
                if evidence_id not in valid_evidence_ids:
                    errors.append(_context(case_id, step_no) + f"unknown evidence_id {evidence_id!r}")
                elif check_evidence_time and expected is not None and case_id in request_by_id:
                    audit_at = request_by_id[case_id].audit_at
                    times = evidence_times.get(evidence_id, [])
                    if times and not any(timestamp <= audit_at for timestamp in times):
                        first_after = min(times)
                        errors.append(
                            _context(case_id, step_no)
                            + f"evidence_id {evidence_id!r} is captured after audit_at ({first_after.isoformat()} > {audit_at.isoformat()})"
                        )

            if deletion_status == "COMPLETE":
                if phase != "VERIFICATION":
                    errors.append(_context(case_id, step_no) + "COMPLETE rows may contain only VERIFICATION steps")
                if not isinstance(evidence_id, str) or not evidence_id.strip():
                    errors.append(_context(case_id, step_no) + "COMPLETE steps require a non-empty evidence_id")
            elif deletion_status == "INCOMPLETE":
                if phase == "FINDING" and (not isinstance(evidence_id, str) or not evidence_id.strip()):
                    errors.append(_context(case_id, step_no) + "INCOMPLETE FINDING steps require a non-empty evidence_id")
                if phase in ("REMEDIATION", "VERIFICATION") and evidence_id != "":
                    errors.append(_context(case_id, step_no) + f"INCOMPLETE {phase} steps require evidence_id == ''")

    return errors


def validate_output_file(
    path: str | Path,
    *,
    expect_requests_path: str | Path | None = None,
    dataset_dir: str | Path = DATASET_DIR,
    check_evidence_time: bool = True,
) -> list[str]:
    """Validate a CSV file, returning an empty list when it is valid."""

    source = Path(path)
    try:
        content = source.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        return [_context("<file>") + f"could not read {source}: {exc}"]
    return validate_output_text(
        content,
        expect_requests_path=expect_requests_path,
        dataset_dir=dataset_dir,
        check_evidence_time=check_evidence_time,
    )
