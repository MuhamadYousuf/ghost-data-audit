"""Typed, standard-library-only CSV loaders for participant-facing inputs."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from .models import (
    Activity,
    AuditLogEntry,
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
    Identity,
    OutputRow,
    Step,
)
from .paths import DATASET_DIR, dataset_file


T = TypeVar("T")


def _read_records(path: str | Path, fields: tuple[str, ...]) -> list[tuple[int, dict[str, str]]]:
    source = Path(path)
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError(f"{source}: CSV is empty; expected header {','.join(fields)}") from None
        if tuple(header) != fields:
            raise ValueError(f"{source}: expected header {','.join(fields)}; found {','.join(header)}")

        records: list[tuple[int, dict[str, str]]] = []
        for line_number, values in enumerate(reader, start=2):
            if len(values) != len(fields):
                raise ValueError(
                    f"{source}: row {line_number}: expected {len(fields)} columns, found {len(values)}"
                )
            records.append((line_number, dict(zip(fields, values))))
    return records


def _timestamp(value: str, *, path: Path, line_number: int, field: str) -> datetime:
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{path}: row {line_number}: invalid {field} timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{path}: row {line_number}: {field} timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _load(path: str | Path, fields: tuple[str, ...], factory: Callable[[dict[str, str], int, Path], T]) -> list[T]:
    source = Path(path)
    return [factory(row, line_number, source) for line_number, row in _read_records(source, fields)]


REQUEST_FIELDS = (
    "case_id",
    "email",
    "requested_at",
    "reported_status",
    "reported_at",
    "audit_at",
    "request_text",
)
IDENTITY_FIELDS = ("user_id", "name", "email", "phone", "email_hash", "updated_at")
AUDIT_FIELDS = ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value")
ACTIVITY_FIELDS = (
    "activity_id",
    "event_time",
    "event_type",
    "source_system",
    "target_system",
    "resource_id",
    "reported_result",
    "details",
)
RULE_FIELDS = ("rule_id", "data_category", "condition", "required_action")
EVIDENCE_FIELDS = ("file_id", "file_path", "origin", "captured_at")
OUTPUT_FIELDS = ("case_id", "deletion_status", "steps_json")


def load_deletion_requests(path: str | Path | None = None) -> list[DeletionRequest]:
    source = Path(path) if path is not None else dataset_file("deletion_requests.csv")

    def make(row: dict[str, str], line: int, file_path: Path) -> DeletionRequest:
        return DeletionRequest(
            case_id=row["case_id"],
            email=row["email"],
            requested_at=_timestamp(row["requested_at"], path=file_path, line_number=line, field="requested_at"),
            reported_status=row["reported_status"],
            reported_at=_timestamp(row["reported_at"], path=file_path, line_number=line, field="reported_at"),
            audit_at=_timestamp(row["audit_at"], path=file_path, line_number=line, field="audit_at"),
            request_text=row["request_text"],
        )

    return _load(source, REQUEST_FIELDS, make)


def load_sample_deletion_requests(path: str | Path | None = None) -> list[DeletionRequest]:
    source = Path(path) if path is not None else dataset_file("sample_deletion_requests.csv")
    return load_deletion_requests(source)


def load_identities(path: str | Path | None = None) -> list[Identity]:
    source = Path(path) if path is not None else dataset_file("user_identities.csv")

    def make(row: dict[str, str], line: int, file_path: Path) -> Identity:
        return Identity(
            user_id=row["user_id"],
            name=row["name"],
            email=row["email"],
            phone=row["phone"],
            email_hash=row["email_hash"],
            updated_at=_timestamp(row["updated_at"], path=file_path, line_number=line, field="updated_at"),
        )

    return _load(source, IDENTITY_FIELDS, make)


def load_audit_log(path: str | Path | None = None) -> list[AuditLogEntry]:
    source = Path(path) if path is not None else dataset_file("user_audit_log.csv")

    def make(row: dict[str, str], line: int, file_path: Path) -> AuditLogEntry:
        return AuditLogEntry(
            audit_id=row["audit_id"],
            user_id=row["user_id"],
            event_time=_timestamp(row["event_time"], path=file_path, line_number=line, field="event_time"),
            field_name=row["field_name"],
            old_value=row["old_value"],
            new_value=row["new_value"],
        )

    return _load(source, AUDIT_FIELDS, make)


def load_activities(path: str | Path | None = None) -> list[Activity]:
    source = Path(path) if path is not None else dataset_file("system_activity.csv")

    def make(row: dict[str, str], line: int, file_path: Path) -> Activity:
        return Activity(
            activity_id=row["activity_id"],
            event_time=_timestamp(row["event_time"], path=file_path, line_number=line, field="event_time"),
            event_type=row["event_type"],
            source_system=row["source_system"],
            target_system=row["target_system"],
            resource_id=row["resource_id"],
            reported_result=row["reported_result"],
            details=row["details"],
        )

    return _load(source, ACTIVITY_FIELDS, make)


def load_deletion_rules(path: str | Path | None = None) -> list[DeletionRule]:
    source = Path(path) if path is not None else dataset_file("deletion_rules.csv")

    def make(row: dict[str, str], _line: int, _file_path: Path) -> DeletionRule:
        return DeletionRule(
            rule_id=row["rule_id"],
            data_category=row["data_category"],
            condition=row["condition"],
            required_action=row["required_action"],
        )

    return _load(source, RULE_FIELDS, make)


def load_evidence_files(path: str | Path | None = None) -> list[EvidenceFile]:
    source = Path(path) if path is not None else dataset_file("evidence_files.csv")

    def make(row: dict[str, str], line: int, file_path: Path) -> EvidenceFile:
        return EvidenceFile(
            file_id=row["file_id"],
            file_path=row["file_path"],
            origin=row["origin"],
            captured_at=_timestamp(row["captured_at"], path=file_path, line_number=line, field="captured_at"),
        )

    return _load(source, EVIDENCE_FIELDS, make)


def _step_from_object(item: object, *, path: Path, line_number: int, index: int) -> Step:
    if not isinstance(item, dict):
        raise ValueError(f"{path}: row {line_number}: step {index} must be a JSON object")
    try:
        return Step(
            step_no=item["step_no"],
            phase=item["phase"],
            system_id=item["system_id"],
            resource_id=item["resource_id"],
            operation=item["operation"],
            state=item["state"],
            evidence_id=item["evidence_id"],
        )
    except KeyError as exc:
        raise ValueError(f"{path}: row {line_number}: step {index} is missing {exc.args[0]!r}") from exc


def load_output_rows(path: str | Path) -> list[OutputRow]:
    """Load a prediction CSV into typed rows; use validate.py for diagnostics."""

    source = Path(path)
    records = _read_records(source, OUTPUT_FIELDS)
    result: list[OutputRow] = []
    for line_number, row in records:
        try:
            items = json.loads(row["steps_json"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}: row {line_number}: invalid steps_json: {exc.msg}") from exc
        if not isinstance(items, list):
            raise ValueError(f"{source}: row {line_number}: steps_json must be a JSON array")
        result.append(
            OutputRow(
                case_id=row["case_id"],
                deletion_status=row["deletion_status"],
                steps=tuple(
                    _step_from_object(item, path=source, line_number=line_number, index=index)
                    for index, item in enumerate(items, start=1)
                ),
            )
        )
    return result


def load_sample_output(path: str | Path | None = None) -> list[OutputRow]:
    source = Path(path) if path is not None else dataset_file("sample_output.csv")
    return load_output_rows(source)


def load_output_template(path: str | Path | None = None) -> list[OutputRow]:
    source = Path(path) if path is not None else DATASET_DIR / "output.csv"
    return load_output_rows(source)
