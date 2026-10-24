"""Current and historical identity profiles for exact request resolution."""

import hashlib
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence

from .loaders import load_audit_log, load_identities
from .models import AuditLogEntry, DeletionRequest, Identity, IdentityProfile


EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
HASH_RE = re.compile(r"[A-F0-9]{64}", re.IGNORECASE)
INVALID_VALUES = frozenset({"", "-", "none", "null", "n/a", "unknown", "[redacted]"})


class IdentityResolutionError(ValueError):
    """Raised when a request email does not resolve to exactly one subject."""


def _clean(value: str) -> str:
    return value.strip()


def _valid_email(value: str) -> str | None:
    text = _clean(value)
    if text.casefold() in INVALID_VALUES or not EMAIL_RE.fullmatch(text):
        return None
    return text


def _valid_hash(value: str) -> str | None:
    text = _clean(value)
    if text.casefold() in INVALID_VALUES or not HASH_RE.fullmatch(text):
        return None
    return text.lower()


def _valid_phone(value: str) -> str | None:
    text = _clean(value)
    if text.casefold() in INVALID_VALUES or "\n" in text or "\r" in text:
        return None
    digits = re.sub(r"\D", "", text)
    if 7 <= len(digits) <= 15:
        return text
    return None


def normalize_email(value: str) -> str:
    return value.strip().casefold()


def normalize_phone(value: str) -> str:
    return re.sub(r"\D", "", value)


def _email_hash(email: str) -> str:
    return hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()


def build_identity_profiles(
    identities: Sequence[Identity] | None = None,
    audit_entries: Sequence[AuditLogEntry] | None = None,
) -> dict[str, IdentityProfile]:
    """Build immutable profiles from current identities and all audit values."""

    identity_rows = list(identities) if identities is not None else load_identities()
    audit_rows = list(audit_entries) if audit_entries is not None else load_audit_log()
    by_user: dict[str, Identity] = {}
    for identity in identity_rows:
        if identity.user_id in by_user:
            raise ValueError(f"duplicate current identity for {identity.user_id}")
        by_user[identity.user_id] = identity

    emails: dict[str, set[str]] = defaultdict(set)
    phones: dict[str, set[str]] = defaultdict(set)
    hashes: dict[str, set[str]] = defaultdict(set)
    names: dict[str, set[str]] = defaultdict(set)

    for user_id, identity in by_user.items():
        email = _valid_email(identity.email)
        if email:
            emails[user_id].add(email)
        phone = _valid_phone(identity.phone)
        if phone:
            phones[user_id].add(phone)
        email_hash = _valid_hash(identity.email_hash)
        if email_hash:
            hashes[user_id].add(email_hash)
        name = _clean(identity.name)
        if name and name.casefold() not in INVALID_VALUES and "\n" not in name and "\r" not in name:
            names[user_id].add(name)

    for entry in audit_rows:
        if entry.user_id not in by_user:
            continue
        field = re.sub(r"[^a-z0-9]+", "_", entry.field_name.casefold()).strip("_")
        values = (entry.old_value, entry.new_value)
        if "email_hash" in field or field in {"hash", "emailhash"}:
            for value in values:
                valid = _valid_hash(value)
                if valid:
                    hashes[entry.user_id].add(valid)
        elif "email" in field:
            for value in values:
                valid = _valid_email(value)
                if valid:
                    emails[entry.user_id].add(valid)
        elif "phone" in field or "mobile" in field or "telephone" in field:
            for value in values:
                valid = _valid_phone(value)
                if valid:
                    phones[entry.user_id].add(valid)
        elif "name" in field:
            for value in values:
                name = _clean(value)
                if name and name.casefold() not in INVALID_VALUES and "\n" not in name and "\r" not in name:
                    names[entry.user_id].add(name)

    profiles: dict[str, IdentityProfile] = {}
    for user_id, identity in sorted(by_user.items()):
        original_emails = frozenset(sorted(emails[user_id]))
        normalized_emails = frozenset(normalize_email(value) for value in original_emails)
        email_hashes = set(hashes[user_id])
        email_hashes.update(_email_hash(value) for value in normalized_emails)
        original_phones = frozenset(sorted(phones[user_id]))
        normalized_phones = frozenset(
            normalized
            for value in original_phones
            if (normalized := normalize_phone(value)) and 7 <= len(normalized) <= 15
        )
        profiles[user_id] = IdentityProfile(
            user_id=user_id,
            current_name=identity.name,
            current_email=identity.email,
            current_phone=identity.phone,
            current_email_hash=identity.email_hash,
            names=frozenset(sorted(names[user_id])),
            emails=original_emails,
            normalized_emails=normalized_emails,
            phones=original_phones,
            normalized_phones=normalized_phones,
            email_hashes=frozenset(sorted(email_hashes)),
        )
    return profiles


def resolve_request(
    request: DeletionRequest,
    profiles: Mapping[str, IdentityProfile] | Sequence[IdentityProfile] | None = None,
) -> str:
    """Resolve a request by case-insensitive exact current or historical email."""

    profile_values = build_identity_profiles().values() if profiles is None else profiles
    values = profile_values.values() if isinstance(profile_values, Mapping) else profile_values
    email = normalize_email(request.email)
    matches = sorted(profile.user_id for profile in values if email in profile.normalized_emails)
    if len(matches) != 1:
        if not matches:
            raise IdentityResolutionError(f"request email did not match any current or historical identity")
        raise IdentityResolutionError(
            f"request email matched multiple users; refusing to guess: {', '.join(matches)}"
        )
    return matches[0]
