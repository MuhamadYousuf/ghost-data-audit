"""Command-line entry point for output generation and validation."""

import argparse
import csv
import json
import sys
from pathlib import Path

from audit.contract import OUTPUT_HEADER
from audit.paths import REPO_ROOT
from audit.validate import validate_output_file


def _write_placeholder_output(path: Path) -> None:
    """Write the output header without inventing any deletion decisions."""

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(OUTPUT_HEADER)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists audit scaffold")
    parser.add_argument("--validate", metavar="PATH", help="validate an existing output CSV and exit")
    parser.add_argument(
        "--inspect-evidence",
        action="store_true",
        help="parse evidence files and print deterministic per-file observation counts",
    )
    parser.add_argument(
        "--explain-case",
        metavar="CASE_ID",
        help="resolve a request and explain its identity-linked resources",
    )
    parser.add_argument(
        "--expect-requests",
        metavar="PATH",
        help="require one output row per request and match that file's case order",
    )
    parser.add_argument(
        "--no-evidence-time-check",
        action="store_true",
        help="skip cited-evidence cutoff checks when an expected requests file is supplied",
    )
    return parser


def _inspect_evidence() -> int:
    from audit.evidence import parse_all_evidence

    corpus = parse_all_evidence()
    headers = ("file_id", "format", "observations", "resources", "systems_seen", "unrecognized")
    rows: list[tuple[str, ...]] = []
    for item in corpus.files:
        rows.append(
            (
                item.file_id,
                item.format,
                str(len(item.observations)),
                str(len(item.distinct_resources)),
                ",".join(sorted(item.systems_seen)) or "-",
                str(item.unrecognized_count),
            )
        )

    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))

    observations = corpus.observations
    resources = {item.resource_id for item in observations if item.resource_id}
    systems = {item.system_id for item in observations if item.system_id}
    unrecognized = sum(item.unrecognized_count for item in corpus.files)
    total_row = (
        f"TOTAL ({len(corpus.files)} files)",
        "-",
        str(len(observations)),
        str(len(resources)),
        ",".join(sorted(systems)) or "-",
        str(unrecognized),
    )
    total_widths = [max(width, len(value)) for width, value in zip(widths, total_row)]
    print("  ".join(value.ljust(total_widths[index]) for index, value in enumerate(total_row)))
    return 0


def _explain_case(case_id: str) -> int:
    from audit.evidence import parse_all_evidence
    from audit.identity import IdentityResolutionError, build_identity_profiles, resolve_request
    from audit.linking import link_resources
    from audit.loaders import load_activities, load_deletion_requests, load_sample_deletion_requests

    requests = load_deletion_requests()
    request = next((item for item in requests if item.case_id == case_id), None)
    if request is None:
        request = next(
            (item for item in load_sample_deletion_requests() if item.case_id == case_id),
            None,
        )
    if request is None:
        print(f"Unknown case_id: {case_id}", file=sys.stderr)
        return 2

    profiles = build_identity_profiles()
    try:
        user_id = resolve_request(request, profiles)
    except IdentityResolutionError as exc:
        print(f"Could not resolve {case_id}: {exc}", file=sys.stderr)
        return 1
    profile = profiles[user_id]
    corpus = parse_all_evidence()
    activities = load_activities()
    links = link_resources(request, profile, corpus.observations, activities)

    payload = {
        "case_id": request.case_id,
        "audit_at": request.audit_at.isoformat(),
        "resolved_profile": {
            "user_id": profile.user_id,
            "current_name": profile.current_name,
            "current_email": profile.current_email,
            "current_phone": profile.current_phone,
            "current_email_hash": profile.current_email_hash,
            "historical_names": sorted(profile.names),
            "emails_as_seen": sorted(profile.emails, key=lambda value: (value.casefold(), value)),
            "normalized_emails": sorted(profile.normalized_emails),
            "phones_as_seen": sorted(profile.phones),
            "normalized_phones": sorted(profile.normalized_phones),
            "email_hashes": sorted(profile.email_hashes),
        },
        "linked_resources": [
            {
                "system_id": item.system_id,
                "resource_id": item.resource_id,
                "record_type": item.record_type,
                "matched_identifier": item.matched_identifier,
                "link_kind": item.link_kind,
                "supporting_observation_locators": list(item.supporting_observation_locators),
                "supporting_activity_ids": list(item.supporting_activity_ids),
            }
            for item in links
        ],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.inspect_evidence and (
        args.validate or args.expect_requests or args.no_evidence_time_check or args.explain_case
    ):
        parser.error("--inspect-evidence cannot be combined with other modes")
    if args.explain_case and (args.validate or args.expect_requests or args.no_evidence_time_check):
        parser.error("--explain-case cannot be combined with validation options")
    if args.expect_requests and not args.validate:
        parser.error("--expect-requests requires --validate")
    if args.no_evidence_time_check and not args.validate:
        parser.error("--no-evidence-time-check requires --validate")

    if args.validate:
        errors = validate_output_file(
            args.validate,
            expect_requests_path=args.expect_requests,
            check_evidence_time=not args.no_evidence_time_check,
        )
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        print(f"Valid output CSV: {Path(args.validate)}")
        return 0

    if args.inspect_evidence:
        return _inspect_evidence()

    if args.explain_case:
        return _explain_case(args.explain_case)

    output_path = REPO_ROOT / "output.csv"
    _write_placeholder_output(output_path)
    print(
        f"Wrote {output_path} with the output header only. "
        "Deletion decisions are not implemented in this scaffold."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
