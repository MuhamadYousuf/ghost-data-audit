"""Exact identity-to-resource linking with strict observation time cutoffs."""

import re
from collections import defaultdict
from collections.abc import Iterable

from .evidence.common import (
    EMAIL_RE,
    HASH_RE,
    USER_ID_RE,
    canonical_system_id,
    normalize_identifier,
    record_type_from_record,
)
from .identity import normalize_email, normalize_phone
from .models import Activity, DeletionRequest, IdentityProfile, LinkedResource, Observation


PHONE_VALUE_RE = re.compile(r"[+0-9\s()./-]+")
LINK_EVENT = "LINK_RESOURCE_IDENTITY"
MATCH_PRIORITY = {
    "user_id": 0,
    "email": 1,
    "email_hash": 2,
    "phone": 3,
    "weak_name": 4,
    "activity_user_id": 5,
    "activity_email": 6,
}


def _name_key(value: str) -> str:
    return " ".join(value.split()).casefold()


def _phone_key(value: str) -> str:
    if not PHONE_VALUE_RE.fullmatch(value):
        return ""
    digits = normalize_phone(value)
    return digits if 7 <= len(digits) <= 15 else ""


def _observation_match(
    profile: IdentityProfile, identifiers: Iterable[str]
) -> tuple[str, str] | None:
    candidates: list[tuple[int, str, str]] = []
    normalized_names = {_name_key(value) for value in profile.names}
    for identifier in identifiers:
        value = identifier.strip()
        if not value:
            continue
        lowered = normalize_identifier(value).casefold()
        if lowered == profile.user_id.casefold():
            candidates.append((MATCH_PRIORITY["user_id"], value, "user_id"))
        elif EMAIL_RE.fullmatch(value) and normalize_email(value) in profile.normalized_emails:
            candidates.append((MATCH_PRIORITY["email"], value, "email"))
        elif HASH_RE.fullmatch(value) and lowered in profile.email_hashes:
            candidates.append((MATCH_PRIORITY["email_hash"], value, "email_hash"))
        elif _phone_key(value) and _phone_key(value) in profile.normalized_phones:
            candidates.append((MATCH_PRIORITY["phone"], value, "phone"))
        elif _name_key(value) in normalized_names:
            candidates.append((MATCH_PRIORITY["weak_name"], value, "weak_name"))
    if not candidates:
        return None
    _priority, matched_identifier, link_kind = min(
        candidates,
        key=lambda item: (item[0], item[1].casefold(), item[1]),
    )
    return matched_identifier, link_kind


def _activity_identifiers(details: str) -> tuple[set[str], set[str]]:
    emails = {match.lower() for match in EMAIL_RE.findall(details)}
    user_ids = {match.lower() for match in USER_ID_RE.findall(details)}
    return emails, user_ids


def link_resources(
    request: DeletionRequest,
    profile: IdentityProfile,
    observations: Iterable[Observation],
    activities: Iterable[Activity],
) -> tuple[LinkedResource, ...]:
    """Return exact strong links and explicitly marked weak name-only candidates."""

    grouped: dict[
        tuple[str, str, str, str, str],
        dict[str, set[str]],
    ] = defaultdict(lambda: {"locators": set(), "activity_ids": set()})

    for observation in observations:
        if not observation.resource_id:
            continue
        if observation.file_captured_at > request.audit_at or observation.observed_at > request.audit_at:
            continue
        match = _observation_match(profile, observation.identifiers)
        if match is None:
            continue
        matched_identifier, link_kind = match
        system_id = canonical_system_id(observation.system_id)
        key = (
            system_id,
            observation.resource_id,
            observation.record_type,
            matched_identifier,
            link_kind,
        )
        grouped[key]["locators"].add(observation.locator)

    for activity in activities:
        if activity.event_type.strip().casefold() != LINK_EVENT.casefold():
            continue
        if activity.event_time > request.audit_at or not activity.resource_id:
            continue
        emails, user_ids = _activity_identifiers(activity.details)
        matches: list[tuple[int, str, str]] = []
        matched_users = user_ids & {profile.user_id.casefold()}
        if matched_users:
            user_id = sorted(matched_users)[0]
            matches.append((MATCH_PRIORITY["activity_user_id"], user_id, "activity_user_id"))
        matched_emails = emails & profile.normalized_emails
        if matched_emails:
            email = sorted(matched_emails)[0]
            matches.append((MATCH_PRIORITY["activity_email"], email, "activity_email"))
        if not matches:
            continue
        _priority, matched_identifier, link_kind = min(matches)
        system_id = canonical_system_id(activity.target_system or activity.source_system)
        record_type = record_type_from_record({}, label=activity.resource_id)
        key = (
            system_id,
            activity.resource_id,
            record_type,
            matched_identifier,
            link_kind,
        )
        grouped[key]["activity_ids"].add(activity.activity_id)

    links = [
        LinkedResource(
            system_id=system_id,
            resource_id=resource_id,
            record_type=record_type,
            matched_identifier=matched_identifier,
            link_kind=link_kind,
            supporting_observation_locators=tuple(sorted(values["locators"])),
            supporting_activity_ids=tuple(sorted(values["activity_ids"])),
        )
        for (system_id, resource_id, record_type, matched_identifier, link_kind), values in grouped.items()
    ]
    return tuple(
        sorted(
            links,
            key=lambda item: (
                item.system_id.casefold(),
                item.system_id,
                item.resource_id.casefold(),
                item.resource_id,
                item.record_type,
                MATCH_PRIORITY.get(item.link_kind, 99),
                item.matched_identifier.casefold(),
                item.matched_identifier,
            ),
        )
    )


def linked_resource_ids(links: Iterable[LinkedResource], *, include_weak: bool = False) -> frozenset[str]:
    """Get resource IDs considered linked; weak name-only candidates are opt-in."""

    return frozenset(
        link.resource_id
        for link in links
        if include_weak or link.link_kind != "weak_name"
    )
