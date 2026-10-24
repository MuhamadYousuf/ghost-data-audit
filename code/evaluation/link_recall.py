"""Measure exact resource-link recall and precision on the public sample set."""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "code"))

from audit.evidence import parse_all_evidence  # noqa: E402
from audit.identity import build_identity_profiles, resolve_request  # noqa: E402
from audit.linking import link_resources, linked_resource_ids  # noqa: E402
from audit.loaders import (  # noqa: E402
    load_activities,
    load_sample_deletion_requests,
    load_sample_output,
)
from audit.models import Activity, DeletionRequest, EvidenceCorpus  # noqa: E402


def _expected_by_case() -> dict[str, set[str]]:
    return {
        row.case_id: {step.resource_id for step in row.steps if step.resource_id}
        for row in load_sample_output()
    }


def _miss_reason(
    resource_id: str,
    request: DeletionRequest,
    corpus: EvidenceCorpus,
    activities: list[Activity],
    weak_resource_ids: set[str],
) -> str:
    timely = [
        observation
        for observation in corpus.observations
        if observation.resource_id == resource_id
        and observation.file_captured_at <= request.audit_at
        and observation.observed_at <= request.audit_at
    ]
    if resource_id in weak_resource_ids:
        return "name-only weak match; excluded from confirmed links"
    if timely:
        if not any(observation.identifiers for observation in timely):
            return "no allowed identity identifier in time-bounded evidence; not derivable"
        return "identifier mismatch in time-bounded evidence"
    later = [
        observation
        for observation in corpus.observations
        if observation.resource_id == resource_id
        and (
            observation.file_captured_at > request.audit_at
            or observation.observed_at > request.audit_at
        )
    ]
    if later:
        return "only observed after audit_at"
    activity_rows = [
        activity
        for activity in activities
        if activity.resource_id == resource_id and activity.event_time <= request.audit_at
    ]
    if activity_rows:
        if any(activity.event_type.casefold() == "link_resource_identity" for activity in activity_rows):
            return "only in LINK_RESOURCE_IDENTITY activity; linked identifiers do not match"
        return "only in activity rows without a matching identity-link event"
    return "not present in participant evidence or link activity by audit_at"


def _extra_reason(links) -> str:
    reasons = []
    for link in links:
        if link.link_kind == "weak_name":
            continue
        if link.supporting_observation_locators:
            locators = ", ".join(link.supporting_observation_locators)
            reasons.append(
                f"strong {link.link_kind} match to {link.matched_identifier} at {locators}"
            )
        if link.supporting_activity_ids:
            activity_ids = ", ".join(link.supporting_activity_ids)
            reasons.append(
                f"{link.link_kind} match to {link.matched_identifier} in activity {activity_ids}"
            )
    return "; ".join(sorted(set(reasons))) or "no strong matching support found"


def main() -> int:
    requests = load_sample_deletion_requests()
    expected_by_case = _expected_by_case()
    profiles = build_identity_profiles()
    corpus = parse_all_evidence()
    activities = load_activities()

    predicted_by_case: dict[str, set[str]] = {}
    links_by_case = {}
    weak_by_case: dict[str, set[str]] = {}
    request_by_case = {request.case_id: request for request in requests}
    for request in requests:
        user_id = resolve_request(request, profiles)
        links = link_resources(request, profiles[user_id], corpus.observations, activities)
        links_by_case[request.case_id] = links
        predicted_by_case[request.case_id] = set(linked_resource_ids(links))
        weak_by_case[request.case_id] = {
            link.resource_id for link in links if link.link_kind == "weak_name"
        } - predicted_by_case[request.case_id]

    true_positive = sum(
        len(predicted_by_case[case_id] & expected)
        for case_id, expected in expected_by_case.items()
    )
    expected_count = sum(len(resources) for resources in expected_by_case.values())
    predicted_count = sum(len(resources) for resources in predicted_by_case.values())
    recall = true_positive / expected_count if expected_count else 0.0
    precision = true_positive / predicted_count if predicted_count else 0.0
    print(f"Sample cases: {len(requests)}")
    print(f"Expected resource links: {expected_count}")
    print(f"Predicted strong resource links: {predicted_count}")
    print(f"True positive links: {true_positive}")
    print(f"Recall: {recall:.4f}")
    print(f"Precision: {precision:.4f}")

    print("\nMISSES")
    miss_count = 0
    for case_id in sorted(expected_by_case):
        missing = expected_by_case[case_id] - predicted_by_case.get(case_id, set())
        for resource_id in sorted(missing):
            miss_count += 1
            reason = _miss_reason(
                resource_id,
                request_by_case[case_id],
                corpus,
                activities,
                weak_by_case.get(case_id, set()),
            )
            print(f"{case_id}\t{resource_id}\t{reason}")
    if not miss_count:
        print("(none)")

    print("\nEXTRAS")
    extra_count = 0
    for case_id in sorted(expected_by_case):
        extra = predicted_by_case.get(case_id, set()) - expected_by_case[case_id]
        links = links_by_case[case_id]
        for resource_id in sorted(extra):
            extra_count += 1
            supporting = [link for link in links if link.resource_id == resource_id]
            print(f"{case_id}\t{resource_id}\t{_extra_reason(supporting)}")
    if not extra_count:
        print("(none)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
