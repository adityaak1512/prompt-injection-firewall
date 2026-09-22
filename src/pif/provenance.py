"""Layer 3: provenance. The invariant that makes trust labels tamper-proof.

Trust levels (see context.py) are only useful if the model can actually
tell, when it reads the final prompt, which parts were DATA. This layer
draws a random, unguessable marker for every single request and wraps
every DATA span in it:

    <<<UNTRUSTED-a3f9c1e0d47b2856 origin=ticket:8814>>>
    ... untrusted content, verbatim ...
    <<<END-a3f9c1e0d47b2856>>>

A *fixed* delimiter (like "---UNTRUSTED---") would be forgeable by any
attacker who has read this source file, which for an open-source project
is everyone. A nonce drawn fresh from a CSPRNG for every request cannot
be predicted in advance. So if that exact nonce ever shows up *inside*
a DATA span's own content, that is not a coincidence and not something
that needs interpreting — it means someone crafted their payload after
having already seen a rendered prompt from this system (e.g. by reading
back a previous response), which is a real attack against the fence
itself. That is why it's reported as CRITICAL and invariant, not scored.
"""

from __future__ import annotations

import secrets

from pif.context import Context, Trust
from pif.verdict import Finding, Severity

NONCE_BYTES = 8


def new_nonce() -> str:
    return secrets.token_hex(NONCE_BYTES)


def fence(text: str, origin_str: str, nonce: str) -> str:
    return f"<<<UNTRUSTED-{nonce} origin={origin_str}>>>\n{text}\n<<<END-{nonce}>>>"


def render(ctx: Context, nonce: str) -> str:
    """Builds the final prompt string sent to the model: SYSTEM and USER
    spans pass through untouched, every DATA span gets fenced."""
    parts: list[str] = []
    for span in ctx.spans:
        if span.trust is Trust.DATA:
            origin_str = str(span.origin) if span.origin else "unknown"
            parts.append(fence(span.text, origin_str, nonce))
        else:
            parts.append(span.text)
    return "\n\n".join(parts)


def check_nonce_forgery(ctx: Context, nonce: str) -> list[Finding]:
    """The invariant check: does the nonce we're about to fence with
    already appear inside the raw (unfenced) content of any DATA span?
    If so, the fence itself can't be trusted for this request."""
    findings: list[Finding] = []
    for span in ctx.data_spans():
        if nonce in span.text:
            findings.append(
                Finding(
                    layer="provenance",
                    rule="nonce-forgery",
                    severity=Severity.CRITICAL,
                    invariant=True,
                    detail=f"origin={span.origin}",
                )
            )
    return findings
