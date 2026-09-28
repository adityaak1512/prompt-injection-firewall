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
    parts: list[str] = []
    for span in ctx.spans:
        if span.trust is Trust.DATA:
            origin_str = str(span.origin) if span.origin else "unknown"
            parts.append(fence(span.text, origin_str, nonce))
        else:
            parts.append(span.text)
    return "\n\n".join(parts)


def check_nonce_forgery(ctx: Context, nonce: str) -> list[Finding]:
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
