"""Trust tracking: where did each piece of text come from?

This is the load-bearing idea of the whole project. Instead of trying to
guess whether a string is "malicious," we track its *provenance* — was
it typed by the user, is it the system prompt, or was it pulled in from
somewhere else (a document, an email, a web page, an API response)? That
last category is DATA, and DATA is never trusted, no matter what it says.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Trust(str, Enum):
    """The three trust levels a span of text can carry."""

    SYSTEM = "system"  # written by the developer, fully trusted
    USER = "user"       # typed by the human at the keyboard, trusted to talk about their own request
    DATA = "data"       # pulled in from anywhere else: a file, a ticket, a web page, a tool result. Never trusted.


@dataclass(frozen=True)
class Origin:
    """Where a DATA span came from, for logging and audits.

    channel: a short label for the kind of source ("ticket", "email", "url")
    ref: an identifier within that channel (a ticket number, a URL, a filename)
    """

    channel: str
    ref: str = ""

    def __str__(self) -> str:
        return f"{self.channel}:{self.ref}" if self.ref else self.channel


@dataclass(frozen=True)
class Span:
    """One piece of text plus the trust level it carries."""

    text: str
    trust: Trust
    origin: Origin | None = None


@dataclass(frozen=True)
class Context:
    """An immutable, append-only conversation being built up for the model.

    Each `.system()` / `.user()` / `.data()` call returns a *new* Context
    with one more span appended — nothing is mutated in place. That means
    `tainted_by` can be a plain computed property instead of a flag someone
    has to remember to set: it is derived from the spans that exist, so it
    can never drift out of sync with what's actually in the context.
    """

    spans: tuple[Span, ...] = field(default_factory=tuple)

    def system(self, text: str) -> "Context":
        return Context(self.spans + (Span(text, Trust.SYSTEM),))

    def user(self, text: str) -> "Context":
        return Context(self.spans + (Span(text, Trust.USER),))

    def data(self, text: str, *, origin: Origin) -> "Context":
        return Context(self.spans + (Span(text, Trust.DATA, origin),))

    @property
    def tainted_by(self) -> tuple[Origin, ...]:
        """Every DATA origin that has entered this context so far.

        Non-empty means: this conversation has seen untrusted content,
        and tool authorization should treat it accordingly. There is no
        way to "clear" this short of building a fresh Context — taint
        does not decay, on purpose.
        """
        return tuple(s.origin for s in self.spans if s.trust is Trust.DATA and s.origin is not None)

    @property
    def is_tainted(self) -> bool:
        return len(self.tainted_by) > 0

    def data_spans(self) -> tuple[Span, ...]:
        return tuple(s for s in self.spans if s.trust is Trust.DATA)
