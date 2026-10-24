"""Evidence parsing tests, including the text resource-recall guard."""

import collections
import sys
import unittest
from datetime import timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "code"))

from audit.evidence import parse_all_evidence  # noqa: E402
from audit.evidence.common import RESOURCE_ID_RE  # noqa: E402
from audit.evidence.log_parser import _decode_line, _key_value_fields  # noqa: E402
from audit.paths import DATASET_DIR  # noqa: E402


class TestEvidenceParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = parse_all_evidence()
        cls.by_path = {item.file_path: item for item in cls.corpus.files}

    def _observations(self, file_path: str, resource_id: str):
        return [
            item
            for item in self.by_path[file_path].observations
            if item.resource_id == resource_id
        ]

    def test_manifest_files_are_detected_by_content(self) -> None:
        formats = collections.Counter(item.format for item in self.corpus.files)
        self.assertEqual(
            formats,
            {
                "JSON": 28,
                "LOG": 26,
                "PDF": 4,
                "PNG": 11,
                "SQL": 24,
                "TXT": 1,
            },
        )
        self.assertEqual(len(self.corpus.files), 94)

    def test_text_resource_recall_guard(self) -> None:
        missed_by_file = {}
        fallback_entries = []
        for report in self.corpus.files:
            if report.format == "PNG":
                continue
            if report.format == "PDF":
                raw_text = report.extracted_text
            else:
                raw_text = (DATASET_DIR / report.file_path).read_text(encoding="utf-8-sig")
            expected = set(RESOURCE_ID_RE.findall(raw_text))
            observed = {item.resource_id for item in report.observations if item.resource_id}
            missed = sorted(expected - observed)
            if missed:
                missed_by_file[report.file_path] = missed
            if any("generic text recall fallback" in item for item in report.unrecognized):
                fallback_entries.append(report.file_path)
        self.assertEqual(missed_by_file, {}, f"resource IDs missed by file: {missed_by_file}")
        self.assertEqual(fallback_entries, [], f"generic fallback was needed for: {fallback_entries}")

    def test_unrecognized_records_are_counted_with_explicit_ignore_reasons(self) -> None:
        details = {
            report.file_path: report.unrecognized
            for report in self.corpus.files
            if report.unrecognized
        }
        self.assertGreater(sum(map(len, details.values())), 0)
        for file_path, entries in details.items():
            with self.subTest(file_path=file_path):
                self.assertTrue(all(": ignored " in entry for entry in entries), entries)

    def test_images_are_registered_as_unparsed_media(self) -> None:
        images = [item for item in self.corpus.files if item.format == "PNG"]
        self.assertEqual(len(images), 11)
        for item in images:
            self.assertEqual(len(item.observations), 1)
            self.assertEqual(item.observations[0].record_type, "UNPARSED_MEDIA")
            self.assertEqual(dict(item.observations[0].attributes)["media_status"], "unparsed")

    def test_pdf_text_is_retained_for_later_extraction(self) -> None:
        pdfs = [item for item in self.corpus.files if item.format == "PDF"]
        self.assertEqual(len(pdfs), 4)
        self.assertEqual(len(self.corpus.pdf_text_by_file), 4)
        self.assertTrue(all(item.extracted_text for item in pdfs))

    def test_log_styles_and_observation_times(self) -> None:
        fields = _key_value_fields('message="two words" enabled=true')
        self.assertEqual(fields, {"message": "two words", "enabled": "true"})
        rfc_fields, _, is_rfc5424 = _decode_line(
            "2026-10-01T12:00:00Z <14>1 node-a account_service tr-123 - - state=ready"
        )
        self.assertTrue(is_rfc5424)
        self.assertEqual(rfc_fields.get("service"), "account_service")
        self.assertEqual(rfc_fields.get("trace_id"), "tr-123")
        for observation in self.corpus.observations:
            self.assertEqual(observation.file_captured_at.tzinfo, timezone.utc)
            self.assertEqual(observation.observed_at.tzinfo, timezone.utc)

    def test_sql_failover_rows_keep_their_container(self) -> None:
        file_path = "evidence/databases/customer_accounts_failover_replica_20260902.sql"
        account = self._observations(file_path, "account_005")
        self.assertEqual(len(account), 1)
        self.assertEqual(account[0].container, "customer_profiles_failover_replica")
        self.assertIn("leila.haddad@yahoo.com", account[0].identifiers)
        self.assertFalse(
            any(
                item.resource_id == "account_005" and item.container == "customer_profiles_primary"
                for item in self.by_path[file_path].observations
            )
        )

    def test_service_log_hash_and_trace_join(self) -> None:
        file_path = "evidence/logs/service_events_ap_south_20260915.log"
        analytics = self._observations(file_path, "analytics_9914")
        self.assertTrue(
            any(
                "44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e"
                in item.identifiers
                for item in analytics
            )
        )
        account = self._observations(file_path, "account_9797")
        self.assertTrue(
            any(
                "minjun.kim@gmail.com" in item.identifiers
                and dict(item.attributes).get("http_status") == "404"
                for item in account
            )
        )

    def test_handover_records(self) -> None:
        file_path = "evidence/records/customer_account_handover_20261001.txt"
        search = self._observations(file_path, "search_052")
        self.assertTrue(
            any(
                "novak.tomasz@icloud.com" in item.identifiers
                and dict(item.attributes).get("state") == "FOUND"
                for item in search
            )
        )
        flow = self._observations(file_path, "data_flow_9522")
        self.assertTrue(any(dict(item.attributes).get("state") == "ACTIVE" for item in flow))

    def test_snapshot_subrecord_time_and_support_record(self) -> None:
        file_path = "evidence/records/customer_data_snapshot_bundle_20260917.json"
        account = self._observations(file_path, "account_3866")
        self.assertEqual(len(account), 1)
        self.assertEqual(account[0].observed_at.isoformat(), "2026-09-17T12:00:00+00:00")
        self.assertEqual(account[0].observed_at.tzinfo, timezone.utc)
        support = self._observations(file_path, "support_4707")
        self.assertTrue(
            any(
                dict(item.attributes).get("message_text") == "[REDACTED]"
                and "user_27" in item.identifiers
                for item in support
            )
        )

    def test_resource_lookup_trace_fields(self) -> None:
        file_path = "evidence/logs/resource_lookup_trace_20260926_103856.log"
        flow = self._observations(file_path, "data_flow_4890")
        self.assertTrue(
            any(
                dict(item.attributes).get("enabled") == "true"
                and "mori.ren@gmail.com" in item.identifiers
                for item in flow
            )
        )


if __name__ == "__main__":
    unittest.main()
