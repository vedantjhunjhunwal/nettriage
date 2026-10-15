"""Finding objects produced by the checks, plus correlation helpers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

SEVERITY_ORDER = {"critical": 0, "major": 1, "minor": 2, "info": 3}


@dataclass
class Finding:
    code: str                       # stable machine id, e.g. OSPF_AREA_MISMATCH
    severity: str
    title: str
    devices: Tuple[str, ...]
    evidence: List[str] = field(default_factory=list)
    fix: List[Tuple[str, str]] = field(default_factory=list)      # (device, junos command)
    verify: List[Tuple[str, str]] = field(default_factory=list)   # (device, show command)
    key: str = ""                   # unique identity used for correlation
    caused_by: Optional[str] = None # key of the root-cause finding, if a symptom
    source: str = "config"          # config | capture

    def __post_init__(self):
        if not self.key:
            self.key = f"{self.code}:{'/'.join(self.devices)}"

    @property
    def is_root(self) -> bool:
        return self.caused_by is None

    def to_dict(self) -> dict:
        return {
            "code": self.code, "severity": self.severity, "title": self.title,
            "devices": list(self.devices), "evidence": self.evidence,
            "fix": [f"{d}# {c}" for d, c in self.fix],
            "verify": [f"{d}> {c}" for d, c in self.verify],
            "key": self.key, "caused_by": self.caused_by, "source": self.source,
        }


def sort_findings(fs: List[Finding]) -> List[Finding]:
    return sorted(fs, key=lambda f: (not f.is_root, SEVERITY_ORDER[f.severity], f.code, f.devices))
