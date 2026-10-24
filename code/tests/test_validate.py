"""Contract and loader tests for Milestone 1."""

import csv
import io
import json
import sys
import unittest
from datetime import timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "code"))

from audit.contract import OUTPUT_HEADER  # noqa: E402
from audit.loaders import (  # noqa: E402
    load_activities,
    load_audit_log,
    load_deletion_requests,
    load_deletion_rules,
    load_evidence_files,
    load_identities,
    load_output_template,
    load_sample_deletion_requests,
    load_sample_output,
)
from audit.paths import DATASET_DIR  # noqa: E402
from audit.validate import validate_output_file, validate_output_text  # noqa: E402


SAMPLE_OUTPUT_PATH = DATASET_DIR / "sample_output.csv"
SAMPLE_REQUESTS_PATH = DATASET_DIR / "sample_deletion_requests.csv"


def _csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _encode(rows: list[dict[str, str]], header: tuple[str, ...] = OUTPUT_HEADER) -> str:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=header, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return handle.getvalue()


def _steps(row: dict[str, str]) -> list[dict[str, object]]:
    return json.loads(row["steps_json"])


class TestSampleOutput(unittest.TestCase):
    def test_sample_output_passes_against_sample_requests(self) -> None:
        self.assertEqual(
            validate_output_file(SAMPLE_OUTPUT_PATH, expect_requests_path=SAMPLE_REQUESTS_PATH),
            [],
        )


class TestLoaders(unittest.TestCase):
    def test_dataset_row_counts_and_timestamp_parsing(self) -> None:
        requests = load_deletion_requests()
        samples = load_sample_deletion_requests()
        rules = load_deletion_rules()
        evidence = load_evidence_files()
        activities = load_activities()
        identities = load_identities()
        audit_log = load_audit_log()

        self.assertEqual(len(requests), 518)
        self.assertEqual(len(samples), 32)
        self.assertEqual(len(rules), 15)
        self.assertEqual(len(evidence), 94)
        self.assertEqual(len(activities), 4011)
        self.assertEqual(len(identities), 850)
        self.assertEqual(len(audit_log), 306)
        self.assertEqual(len(load_sample_output()), 32)
        self.assertEqual(load_output_template(), [])

        timestamps = [
            value
            for request in requests + samples
            for value in (request.requested_at, request.reported_at, request.audit_at)
        ]
        timestamps.extend(identity.updated_at for identity in identities)
        timestamps.extend(entry.event_time for entry in audit_log)
        timestamps.extend(activity.event_time for activity in activities)
        timestamps.extend(item.captured_at for item in evidence)
        self.assertTrue(timestamps)
        for timestamp in timestamps:
            self.assertIsNotNone(timestamp.tzinfo)
            self.assertEqual(timestamp.tzinfo, timezone.utc)


class TestValidatorCorruptions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows = _csv_rows(SAMPLE_OUTPUT_PATH)

    def _errors(self, rows: list[dict[str, str]], header: tuple[str, ...] = OUTPUT_HEADER) -> list[str]:
        return validate_output_text(
            _encode(rows, header),
            expect_requests_path=SAMPLE_REQUESTS_PATH,
        )

    def _row_with_steps(self, minimum: int = 1) -> dict[str, str]:
        for row in self.rows:
            if len(_steps(row)) >= minimum:
                return dict(row)
        self.fail(f"sample data has no row with at least {minimum} step(s)")

    def test_wrong_header_fails(self) -> None:
        errors = self._errors([dict(row) for row in self.rows], ("wrong", *OUTPUT_HEADER[1:]))
        self.assertTrue(any("header must be exactly" in error for error in errors))

    def test_missing_row_fails(self) -> None:
        errors = self._errors([dict(row) for row in self.rows[:-1]])
        self.assertTrue(any("missing required case_id" in error for error in errors))

    def test_duplicate_row_fails(self) -> None:
        rows = [dict(row) for row in self.rows]
        rows.insert(1, dict(rows[0]))
        errors = self._errors(rows)
        self.assertTrue(any("duplicate case_id" in error for error in errors))

    def test_rows_out_of_numeric_order_fail(self) -> None:
        rows = [dict(row) for row in self.rows]
        rows[0], rows[-1] = rows[-1], rows[0]
        errors = self._errors(rows)
        self.assertTrue(any("CSV row order is not numeric" in error for error in errors))

    def test_steps_out_of_order_fail(self) -> None:
        row = self._row_with_steps(2)
        steps = _steps(row)
        steps[0], steps[1] = steps[1], steps[0]
        row["steps_json"] = json.dumps(steps)
        rows = [dict(item) for item in self.rows]
        index = next(i for i, item in enumerate(rows) if item["case_id"] == row["case_id"])
        rows[index] = row
        errors = self._errors(rows)
        self.assertTrue(any("steps are out of order" in error for error in errors))

    def test_step_number_gap_fails(self) -> None:
        row = self._row_with_steps(2)
        steps = _steps(row)
        steps[1]["step_no"] = steps[1]["step_no"] + 2
        row["steps_json"] = json.dumps(steps)
        rows = [dict(item) for item in self.rows]
        index = next(i for i, item in enumerate(rows) if item["case_id"] == row["case_id"])
        rows[index] = row
        errors = self._errors(rows)
        self.assertTrue(any("step_no must be consecutive" in error for error in errors))

    def test_invalid_triple_fails(self) -> None:
        row = self._row_with_steps()
        steps = _steps(row)
        steps[0]["state"] = "INVALID_STATE"
        row["steps_json"] = json.dumps(steps)
        rows = [dict(item) for item in self.rows]
        index = next(i for i, item in enumerate(rows) if item["case_id"] == row["case_id"])
        rows[index] = row
        errors = self._errors(rows)
        self.assertTrue(any("invalid (phase, operation, state) triple" in error for error in errors))

    def test_complete_with_finding_fails(self) -> None:
        row = next(dict(item) for item in self.rows if any(step["phase"] == "FINDING" for step in _steps(item)))
        row["deletion_status"] = "COMPLETE"
        rows = [dict(item) for item in self.rows]
        index = next(i for i, item in enumerate(rows) if item["case_id"] == row["case_id"])
        rows[index] = row
        errors = self._errors(rows)
        self.assertTrue(any("COMPLETE rows may contain only VERIFICATION steps" in error for error in errors))

    def test_incomplete_remediation_evidence_fails(self) -> None:
        row = next(
            dict(item)
            for item in self.rows
            if item["deletion_status"] == "INCOMPLETE"
            and any(step["phase"] == "REMEDIATION" for step in _steps(item))
        )
        steps = _steps(row)
        remediation = next(step for step in steps if step["phase"] == "REMEDIATION")
        remediation["evidence_id"] = "fabricated-reference"
        row["steps_json"] = json.dumps(steps)
        rows = [dict(item) for item in self.rows]
        index = next(i for i, item in enumerate(rows) if item["case_id"] == row["case_id"])
        rows[index] = row
        errors = self._errors(rows)
        self.assertTrue(any("INCOMPLETE REMEDIATION steps require evidence_id == ''" in error for error in errors))

    def test_unknown_evidence_id_fails(self) -> None:
        row = self._row_with_steps()
        steps = _steps(row)
        steps[0]["evidence_id"] = "unknown-reference"
        row["steps_json"] = json.dumps(steps)
        rows = [dict(item) for item in self.rows]
        index = next(i for i, item in enumerate(rows) if item["case_id"] == row["case_id"])
        rows[index] = row
        errors = self._errors(rows)
        self.assertTrue(any("unknown evidence_id" in error for error in errors))

    def test_not_applicable_with_steps_fails(self) -> None:
        row = self._row_with_steps()
        row["deletion_status"] = "NOT_APPLICABLE"
        rows = [dict(item) for item in self.rows]
        index = next(i for i, item in enumerate(rows) if item["case_id"] == row["case_id"])
        rows[index] = row
        errors = self._errors(rows)
        self.assertTrue(any("NOT_APPLICABLE requires an empty" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
