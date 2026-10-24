"""Frozen typed records for dataset inputs and output steps."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass(frozen=True, slots=True)
class Identity:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class IdentityProfile:
    user_id: str
    current_name: str
    current_email: str
    current_phone: str
    current_email_hash: str
    names: frozenset[str]
    emails: frozenset[str]
    normalized_emails: frozenset[str]
    phones: frozenset[str]
    normalized_phones: frozenset[str]
    email_hashes: frozenset[str]


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True, slots=True)
class Activity:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True, slots=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True, slots=True)
class EvidenceFile:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime


@dataclass(frozen=True, slots=True)
class Step:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str


@dataclass(frozen=True, slots=True)
class OutputRow:
    case_id: str
    deletion_status: str
    steps: tuple[Step, ...]


@dataclass(frozen=True, slots=True)
class Observation:
    file_id: str
    file_captured_at: datetime
    observed_at: datetime
    system_id: str
    resource_id: str
    record_type: str
    container: str
    identifiers: frozenset[str]
    attributes: tuple[tuple[str, str], ...]
    locator: str


@dataclass(frozen=True, slots=True)
class LinkedResource:
    system_id: str
    resource_id: str
    record_type: str
    matched_identifier: str
    link_kind: str
    supporting_observation_locators: tuple[str, ...]
    supporting_activity_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceFileSummary:
    file_id: str
    file_path: str
    format: str
    observations: tuple[Observation, ...]
    unrecognized: tuple[str, ...]
    extracted_text: str = ""

    @property
    def unrecognized_count(self) -> int:
        return len(self.unrecognized)

    @property
    def distinct_resources(self) -> frozenset[str]:
        return frozenset(item.resource_id for item in self.observations if item.resource_id)

    @property
    def systems_seen(self) -> frozenset[str]:
        return frozenset(item.system_id for item in self.observations if item.system_id)


@dataclass(frozen=True, slots=True)
class EvidenceCorpus:
    files: tuple[EvidenceFileSummary, ...]

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(observation for item in self.files for observation in item.observations)

    @property
    def pdf_text_by_file(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (item.file_id, item.extracted_text)
            for item in self.files
            if item.format == "PDF" and item.extracted_text
        )
