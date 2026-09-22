"""Layer 4: tool authorization. The model requests, the firewall decides.

The usual pattern in agent frameworks is "the model asks for a tool, and
the tool runs" — trust is implicit. Here, every tool call the model wants
to make has to clear a guard *before* it runs, and the guard is chosen by
the developer per-tool, not inferred from the request text. This is the
layer that stops the "zero-click" attack shape: a poisoned document tells
the model to call `send_email(to=attacker, body=secret)`, and because the
context is already tainted by that document, the call never executes —
no matter how politely or convincingly the document phrased the request.

Guards never look at *what the tool call says* to decide. They look at
*what the context has already seen* (taint) and *what the developer
declared allowed* (schema/effects). That's what makes this layer hold up
against an attacker who rephrases: rephrasing changes the text, not the
taint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pif.context import Context
from pif.verdict import Finding, Severity


class Guard(str, Enum):
    NONE = "none"
    # Once any DATA span has entered the context, this tool is refused for
    # the rest of the session. Taint never decays, and there's no API to
    # clear it short of starting a brand new Context.
    NO_UNTRUSTED_INFLUENCE = "no_untrusted_influence"
    # Refused unless the *host application* (not the model) has separately
    # confirmed this specific call, e.g. via a real UI click from a human.
    USER_CONFIRMED = "user_confirmed"
    # Arguments are checked against an explicit allow-list of values/keys;
    # anything not declared is refused rather than silently passed through.
    ARGS_ALLOWLISTED = "args_allowlisted"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    guard: Guard = Guard.NONE
    effects: frozenset[str] = frozenset()
    allowed_args: dict[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, str] = field(default_factory=dict)


def authorize(
    call: ToolCall,
    spec: ToolSpec,
    ctx: Context,
    *,
    forbidden_effects: frozenset[str] = frozenset(),
    user_confirmed: bool = False,
) -> list[Finding]:
    """Returns an empty list if the call is authorized, or one or more
    invariant Findings explaining why it isn't. Every path here is a
    structural check — taint, a boolean the host set, or a value not in
    an allow-list — never a read of the call's own text for "intent."""
    findings: list[Finding] = []

    blocked_effects = spec.effects & forbidden_effects
    if blocked_effects:
        findings.append(
            Finding(
                layer="toolauth",
                rule="forbidden-effect",
                severity=Severity.CRITICAL,
                invariant=True,
                detail=f"tool={call.tool} effects={sorted(blocked_effects)}",
            )
        )
        return findings

    if spec.guard is Guard.NO_UNTRUSTED_INFLUENCE and ctx.is_tainted:
        findings.append(
            Finding(
                layer="toolauth",
                rule="tainted-context",
                severity=Severity.CRITICAL,
                invariant=True,
                detail=f"tool={call.tool} tainted_by={[str(o) for o in ctx.tainted_by]}",
            )
        )

    if spec.guard is Guard.USER_CONFIRMED and not user_confirmed:
        findings.append(
            Finding(
                layer="toolauth",
                rule="unconfirmed",
                severity=Severity.HIGH,
                invariant=True,
                detail=f"tool={call.tool}",
            )
        )

    if spec.guard is Guard.ARGS_ALLOWLISTED:
        for key, value in call.args.items():
            allowed_values = spec.allowed_args.get(key)
            if allowed_values is None:
                findings.append(
                    Finding(
                        layer="toolauth",
                        rule="undeclared-argument",
                        severity=Severity.HIGH,
                        invariant=True,
                        detail=f"tool={call.tool} arg={key}",
                    )
                )
            elif value not in allowed_values:
                findings.append(
                    Finding(
                        layer="toolauth",
                        rule="argument-not-allowlisted",
                        severity=Severity.HIGH,
                        invariant=True,
                        detail=f"tool={call.tool} arg={key}={value}",
                    )
                )

    return findings
