"""Command-line entry point for output generation and validation."""

import argparse
import csv
import sys
from pathlib import Path

from audit.contract import OUTPUT_HEADER
from audit.paths import REPO_ROOT
from audit.validate import validate_output_file


def _write_milestone_one_placeholder(path: Path) -> None:
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.inspect_evidence and (args.validate or args.expect_requests or args.no_evidence_time_check):
        parser.error("--inspect-evidence cannot be combined with validation options")
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

    output_path = REPO_ROOT / "output.csv"
    _write_milestone_one_placeholder(output_path)
    print(
        f"Wrote {output_path} with the output header only. "
        "Prediction decisions are intentionally not part of Milestone 1."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
