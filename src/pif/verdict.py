from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Finding:
    layer: str
    rule: str
    severity: Severity
    invariant: bool
    detail: str = ""
    score: int = 0

    def __str__(self) -> str:
        return f"{self.layer}/{self.rule}  {self.severity.value}"


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    elapsed_ms: float = 0.0

    @property
    def blocked_by(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.invariant)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def render(self) -> str:
        lines = [f"{self.decision.value.upper()}  ({self.elapsed_ms:.2f} ms)"]
        for f in self.findings:
            marker = "!" if f.invariant else "-"
            lines.append(f"  {marker} {f.layer}/{f.rule}  {f.severity.value}" + (f"  ({f.detail})" if f.detail else ""))
        return "\n".join(lines)
