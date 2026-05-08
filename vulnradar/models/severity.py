# vulnradar/models/severity.py

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Parse a severity string case-insensitively. Raises ValueError if unknown."""
        mapping = {s.value.lower(): s for s in cls}
        result = mapping.get(value.strip().lower())
        if result is None:
            raise ValueError(f"Unknown severity value: '{value}'")
        return result
