"""Parser for SQL snapshot exports, executed only in an in-memory SQLite DB."""

import json
import sqlite3
from datetime import datetime
from typing import Any

from ..models import EvidenceFile
from .common import make_observations, parse_observation_time, system_id_from_record
from .result import ParserOutput


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def parse_sql(text: str, evidence: EvidenceFile) -> ParserOutput:
    result = ParserOutput()
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(text)
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ]
        scope_times: dict[str, datetime] = {}

        for table in tables:
            if table.casefold() != "snapshot_scope":
                continue
            quoted = _quote_identifier(table)
            cursor = connection.execute(f"SELECT rowid, * FROM {quoted} ORDER BY rowid")
            names = [item[0] for item in cursor.description or ()]
            for ordinal, values in enumerate(cursor, start=1):
                rowid = values[0] if values else ordinal
                row = dict(zip(names[1:], values[1:]))
                system = system_id_from_record(row, container=table)
                captured = parse_observation_time(row.get("captured_at"))
                if system and captured:
                    scope_times[system] = captured
                result.observations.extend(
                    make_observations(
                        row,
                        evidence=evidence,
                        container=table,
                        locator=f"{evidence.file_path}#{table}:{rowid}",
                        inherited_system=system,
                        inherited_time=captured,
                    )
                )

        for table in tables:
            if table.casefold() == "snapshot_scope":
                continue
            quoted = _quote_identifier(table)
            try:
                cursor = connection.execute(f"SELECT rowid, * FROM {quoted} ORDER BY rowid")
            except sqlite3.DatabaseError as exc:
                result.add_unrecognized(f"{evidence.file_path}#{table}", f"table could not be read: {exc}")
                continue
            names = [item[0] for item in cursor.description or ()]
            for ordinal, values in enumerate(cursor, start=1):
                rowid = values[0] if values else ordinal
                row: dict[str, Any] = dict(zip(names[1:], values[1:]))
                payload: dict[str, Any] = {}
                raw_payload = row.get("record_json")
                if isinstance(raw_payload, str) and raw_payload:
                    try:
                        decoded = json.loads(raw_payload)
                        if isinstance(decoded, dict):
                            payload = decoded
                        else:
                            result.add_unrecognized(
                                f"{evidence.file_path}#{table}:{rowid}",
                                "record_json is not a JSON object",
                            )
                    except json.JSONDecodeError:
                        result.add_unrecognized(
                            f"{evidence.file_path}#{table}:{rowid}",
                            "record_json could not be decoded",
                        )
                merged = dict(row)
                merged.update(payload)
                system = system_id_from_record(merged, container=table)
                scope_time = scope_times.get(system)
                result.observations.extend(
                    make_observations(
                        merged,
                        evidence=evidence,
                        container=table,
                        locator=f"{evidence.file_path}#{table}:{rowid}",
                        inherited_system=system,
                        inherited_time=scope_time,
                    )
                )
    except sqlite3.DatabaseError as exc:
        result.add_unrecognized(evidence.file_path, f"SQLite script could not be executed: {exc}")
    finally:
        connection.close()
    return result
