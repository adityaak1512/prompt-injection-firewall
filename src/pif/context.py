from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Trust(str, Enum):
    SYSTEM = "system"
    USER = "user"
    DATA = "data"


@dataclass(frozen=True)
class Origin:
    channel: str
    ref: str = ""

    def __str__(self) -> str:
        return f"{self.channel}:{self.ref}" if self.ref else self.channel


@dataclass(frozen=True)
class Span:
    text: str
    trust: Trust
    origin: Origin | None = None


@dataclass(frozen=True)
class Context:
    spans: tuple[Span, ...] = field(default_factory=tuple)

    def system(self, text: str) -> "Context":
        return Context(self.spans + (Span(text, Trust.SYSTEM),))

    def user(self, text: str) -> "Context":
        return Context(self.spans + (Span(text, Trust.USER),))

    def data(self, text: str, *, origin: Origin) -> "Context":
        return Context(self.spans + (Span(text, Trust.DATA, origin),))

    @property
    def tainted_by(self) -> tuple[Origin, ...]:
        return tuple(s.origin for s in self.spans if s.trust is Trust.DATA and s.origin is not None)

    @property
    def is_tainted(self) -> bool:
        return len(self.tainted_by) > 0

    def data_spans(self) -> tuple[Span, ...]:
        return tuple(s for s in self.spans if s.trust is Trust.DATA)
