"""The output shape every layer reports through.

Every layer, no matter what it checks, reports the same two things:
a list of Findings, and whether any of them are severe enough to block.
Keeping this shape identical across layers is what lets the Firewall
combine five very different checks into one decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    """The three possible outcomes of a firewall check."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class Severity(str, Enum):
    """How serious a single finding is, independent of the final decision."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Finding:
    """One thing a layer noticed.

    `invariant=True` means "this is a hard rule, not a guess" — the kind
    of thing normalize/provenance/toolauth/egress report. If any
    invariant finding exists, the firewall blocks no matter what the
    policy thresholds say. `invariant=False` findings (from ingress) are
    scored and compared against a threshold instead, because ingress is
    the one layer that has to guess at intent from text.
    """

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
    """The result of running the firewall over a Context or a piece of output."""

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
