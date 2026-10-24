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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
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

    output_path = REPO_ROOT / "output.csv"
    _write_milestone_one_placeholder(output_path)
    print(
        f"Wrote {output_path} with the output header only. "
        "Prediction decisions are intentionally not part of Milestone 1."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
