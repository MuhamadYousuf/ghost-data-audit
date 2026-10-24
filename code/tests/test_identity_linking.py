"""Identity history, exact linking, and time-cutoff regression tests."""

import hashlib
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "code"))

from audit.evidence import parse_all_evidence  # noqa: E402
from audit.identity import (  # noqa: E402
    IdentityResolutionError,
    build_identity_profiles,
    normalize_email,
    normalize_phone,
    resolve_request,
)
from audit.linking import linked_resource_ids, link_resources  # noqa: E402
from audit.loaders import (  # noqa: E402
    load_activities,
    load_deletion_requests,
    load_sample_deletion_requests,
)
from audit.models import Activity, IdentityProfile, Observation  # noqa: E402


class TestIdentityAndLinking(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profiles = build_identity_profiles()
        cls.observations = parse_all_evidence().observations
        cls.activities = load_activities()

    def test_every_evaluation_and_sample_request_resolves_once(self) -> None:
        requests = load_deletion_requests() + load_sample_deletion_requests()
        resolved = [resolve_request(request, self.profiles) for request in requests]
        self.assertEqual(len(resolved), len(requests))
        self.assertTrue(all(user_id in self.profiles for user_id in resolved))

    def test_profile_keeps_original_and_normalized_identity_values(self) -> None:
        for profile in self.profiles.values():
            for email in profile.normalized_emails:
                digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
                self.assertIn(digest, profile.email_hashes)
            for phone in profile.phones:
                digits = "".join(character for character in phone if character.isdigit())
                if 7 <= len(digits) <= 15:
                    self.assertIn(digits, profile.normalized_phones)

    def test_email_resolution_is_case_insensitive_and_exact(self) -> None:
        sample = load_sample_deletion_requests()[0]
        expected = resolve_request(sample, self.profiles)
        self.assertEqual(resolve_request(replace(sample, email=sample.email.swapcase()), self.profiles), expected)
        with self.assertRaisesRegex(IdentityResolutionError, "did not match"):
            resolve_request(replace(sample, email="nobody@example.invalid"), self.profiles)

    def test_ambiguous_email_resolution_refuses_to_guess(self) -> None:
        sample = load_sample_deletion_requests()[0]
        email = normalize_email(sample.email)
        first = next(
            profile
            for profile in self.profiles.values()
            if email in profile.normalized_emails
        )
        duplicate = replace(first, user_id="user_test_duplicate")
        with self.assertRaisesRegex(IdentityResolutionError, "multiple users"):
            resolve_request(sample, {first.user_id: first, duplicate.user_id: duplicate})

    def test_decoy_email_is_not_a_fuzzy_match(self) -> None:
        sample = load_sample_deletion_requests()[0]
        base = next(iter(self.profiles.values()))
        profile = replace(
            base,
            user_id="user_decoy_test",
            names=frozenset(),
            emails=frozenset({"g.silva76@gmail.com"}),
            normalized_emails=frozenset({"g.silva76@gmail.com"}),
            phones=frozenset(),
            normalized_phones=frozenset(),
            email_hashes=frozenset(),
        )
        observation = Observation(
            file_id="synthetic",
            file_captured_at=sample.audit_at,
            observed_at=sample.audit_at,
            system_id="search_service",
            resource_id="search_999999",
            record_type="SEARCH_INDEX_ENTRY",
            container="synthetic",
            identifiers=frozenset({"g.silva76.jr@gmail.com"}),
            attributes=(),
            locator="synthetic:1",
        )
        links = link_resources(sample, profile, (observation,), ())
        self.assertEqual(links, ())

    def test_all_strong_observation_identifier_kinds_link_exactly(self) -> None:
        request = load_sample_deletion_requests()[0]
        profile = self.profiles[resolve_request(request, self.profiles)]
        email = next(iter(profile.normalized_emails))
        phone = next(iter(profile.phones))
        email_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()
        values = (
            ("account_999991", email.upper(), "email"),
            ("account_999992", profile.user_id, "user_id"),
            ("analytics_999993", email_hash, "email_hash"),
            ("support_999994", phone, "phone"),
        )
        observations = tuple(
            Observation(
                file_id="synthetic",
                file_captured_at=request.audit_at,
                observed_at=request.audit_at,
                system_id="account_service",
                resource_id=resource_id,
                record_type="",
                container="synthetic",
                identifiers=frozenset({identifier}),
                attributes=(),
                locator=f"synthetic:{index}",
            )
            for index, (resource_id, identifier, _kind) in enumerate(values, start=1)
        )
        links = link_resources(request, profile, observations, ())
        found = {item.resource_id: item.link_kind for item in links}
        self.assertEqual(
            found,
            {resource_id: expected_kind for resource_id, _identifier, expected_kind in values},
        )
        self.assertIn(normalize_phone(phone), profile.normalized_phones)

    def test_file_capture_and_record_time_both_obey_cutoff(self) -> None:
        sample = load_sample_deletion_requests()[0]
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        before = datetime(2025, 12, 31, tzinfo=timezone.utc)
        after = datetime(2026, 1, 2, tzinfo=timezone.utc)
        request = replace(sample, audit_at=cutoff)
        profile = next(iter(self.profiles.values()))
        late_capture = Observation(
            file_id="late",
            file_captured_at=after,
            observed_at=before,
            system_id="account_service",
            resource_id="account_999998",
            record_type="USER_PROFILE",
            container="late",
            identifiers=frozenset(profile.normalized_emails),
            attributes=(),
            locator="late:1",
        )
        late_record = replace(
            late_capture,
            file_id="early",
            file_captured_at=before,
            observed_at=after,
            locator="early:1",
        )
        self.assertEqual(link_resources(request, profile, (late_capture, late_record), ()), ())

    def test_activity_identity_link_uses_exact_details_and_time_cutoff(self) -> None:
        request = load_sample_deletion_requests()[0]
        profile = self.profiles[resolve_request(request, self.profiles)]
        activity = Activity(
            activity_id="synthetic_activity",
            event_time=request.audit_at,
            event_type="LINK_RESOURCE_IDENTITY",
            source_system="data_catalog",
            target_system="support_platform",
            resource_id="support_999996",
            reported_result="linked",
            details=f"Catalog linked the resource to {request.email.upper()} and {profile.user_id}.",
        )
        late = replace(
            activity,
            activity_id="synthetic_late_activity",
            event_time=request.audit_at.replace(year=request.audit_at.year + 1),
        )
        links = link_resources(request, profile, (), (activity, late))
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].resource_id, "support_999996")
        self.assertEqual(links[0].link_kind, "activity_user_id")
        self.assertEqual(links[0].matched_identifier, profile.user_id)
        self.assertEqual(links[0].supporting_observation_locators, ())
        self.assertEqual(links[0].supporting_activity_ids, ("synthetic_activity",))

    def test_historical_email_hash_links_analytics_resource(self) -> None:
        email = "minjun.kim@gmail.com"
        request = next(
            item
            for item in load_sample_deletion_requests()
            if normalize_email(item.email) == email
        )
        profile = self.profiles[resolve_request(request, self.profiles)]
        historical_emails = profile.normalized_emails - {email}
        expected_hashes = {
            hashlib.sha256(value.encode("utf-8")).hexdigest()
            for value in historical_emails
        }
        self.assertIn(email, profile.normalized_emails)
        self.assertTrue(expected_hashes.intersection(profile.email_hashes))

        links = link_resources(request, profile, self.observations, self.activities)
        analytics = [
            item
            for item in links
            if item.resource_id == "analytics_9914" and item.link_kind == "email_hash"
        ]
        self.assertTrue(analytics)
        self.assertTrue(
            any(item.matched_identifier in expected_hashes for item in analytics),
            "analytics resource should match the SHA-256 of a historical email",
        )

    def test_name_only_matches_are_marked_weak_and_not_counted_as_strong(self) -> None:
        sample = load_sample_deletion_requests()[0]
        profile = next(iter(self.profiles.values()))
        name = next(iter(profile.names))
        observation = Observation(
            file_id="synthetic",
            file_captured_at=sample.audit_at,
            observed_at=sample.audit_at,
            system_id="support_platform",
            resource_id="support_999997",
            record_type="SUPPORT_MESSAGE",
            container="synthetic",
            identifiers=frozenset({name}),
            attributes=(),
            locator="synthetic:2",
        )
        links = link_resources(sample, profile, (observation,), ())
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].link_kind, "weak_name")
        self.assertEqual(linked_resource_ids(links), frozenset())
        self.assertEqual(linked_resource_ids(links, include_weak=True), {"support_999997"})


if __name__ == "__main__":
    unittest.main()
