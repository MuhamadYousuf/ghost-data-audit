"""Output contract constants shared by the CLI, validator, and tests."""

from types import MappingProxyType


OUTPUT_HEADER = ("case_id", "deletion_status", "steps_json")

PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")
PHASE_ORDER = MappingProxyType({phase: index for index, phase in enumerate(PHASES)})

DELETION_STATUSES = frozenset(("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"))

OPERATION_ORDER = MappingProxyType(
    {
        "FINDING": (
            "REPORT_REMAINING_RECORD",
            "REPORT_EXPOSED_PII",
            "REPORT_ACTIVE_DATA_FLOW",
            "REPORT_RESTORE_RISK",
        ),
        "REMEDIATION": (
            "DISABLE_DATA_FLOW",
            "BLOCK_RESTORE",
            "DELETE_RECORD",
            "REDACT_RECORD",
            "ANONYMIZE_RECORD",
        ),
        "VERIFICATION": (
            "VERIFY_RECORD_ABSENT",
            "VERIFY_RECORD_PRESENT",
            "VERIFY_RECORD_REDACTED",
            "VERIFY_RECORD_ANONYMIZED",
            "VERIFY_DATA_FLOW_DISABLED",
            "VERIFY_RESTORE_BLOCKED",
        ),
    }
)

ALLOWED_STEP_TRIPLES = frozenset(
    {
        ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
        ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
        ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
        ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
        ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
        ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
        ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
        ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
        ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
        ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
        ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
        ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
        ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
        ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
        ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    }
)

STEP_FIELDS = frozenset(
    ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
)
