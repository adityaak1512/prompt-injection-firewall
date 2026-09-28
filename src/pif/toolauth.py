from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pif.context import Context
from pif.verdict import Finding, Severity


class Guard(str, Enum):
    NONE = "none"
    NO_UNTRUSTED_INFLUENCE = "no_untrusted_influence"
    USER_CONFIRMED = "user_confirmed"
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
