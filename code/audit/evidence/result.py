"""Mutable per-file accumulator used internally by evidence parsers."""

from dataclasses import dataclass, field

from ..models import Observation


@dataclass(slots=True)
class ParserOutput:
    observations: list[Observation] = field(default_factory=list)
    unrecognized: list[str] = field(default_factory=list)
    extracted_text: str = ""

    def add_unrecognized(self, locator: str, reason: str) -> None:
        self.unrecognized.append(f"{locator}: {reason}")
