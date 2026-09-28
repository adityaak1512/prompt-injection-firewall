from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

_ZERO_WIDTH = dict.fromkeys(
    ord(c) for c in [
        "​", "‌", "‍", "﻿", "⁠",
    ]
)

_BIDI_CONTROLS = dict.fromkeys(
    ord(c) for c in [
        "‪", "‫", "‬", "‭", "‮",
        "⁦", "⁧", "⁨", "⁩",
    ]
)

_TAG_BLOCK_LOW = 0xE0000
_TAG_BLOCK_HIGH = 0xE007F

_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "ı": "i", "а": "a",
}

_B64_TOKEN = re.compile(r"\b(?:[A-Za-z0-9+/]{16,}={0,2})\b")
_HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_MAX_PASSES = 6


@dataclass
class NormalizeResult:
    text: str
    findings: list[str] = field(default_factory=list)


def _strip_tag_block(text: str) -> tuple[str, bool]:
    out = []
    found = False
    for ch in text:
        cp = ord(ch)
        if _TAG_BLOCK_LOW <= cp <= _TAG_BLOCK_HIGH:
            found = True
            shifted = cp - _TAG_BLOCK_LOW
            if 0x20 <= shifted <= 0x7E:
                out.append(chr(shifted))
        else:
            out.append(ch)
    return "".join(out), found


def _strip_invisibles(text: str) -> tuple[str, bool]:
    found = any(ord(c) in _ZERO_WIDTH or ord(c) in _BIDI_CONTROLS for c in text)
    if not found:
        return text, False
    cleaned = "".join(c for c in text if ord(c) not in _ZERO_WIDTH and ord(c) not in _BIDI_CONTROLS)
    return cleaned, True


def _fold_confusables(text: str) -> tuple[str, bool]:
    found = any(c in _CONFUSABLES for c in text)
    if not found:
        return text, False
    return "".join(_CONFUSABLES.get(c, c) for c in text), True


def _try_decode_token(token: str) -> str | None:
    candidates = []
    try:
        padded = token + "=" * (-len(token) % 4)
        candidates.append(base64.b64decode(padded, validate=False))
    except (binascii.Error, ValueError):
        pass
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", token):
        try:
            candidates.append(bytes.fromhex(token))
        except ValueError:
            pass
    for raw in candidates:
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
        if decoded and printable / len(decoded) > 0.85:
            return decoded
    return None


def _decode_embedded_blobs(text: str) -> tuple[str, bool]:
    found = False
    revealed = []
    for pattern in (_B64_TOKEN, _HEX_TOKEN):
        for m in pattern.finditer(text):
            decoded = _try_decode_token(m.group())
            if decoded and decoded != m.group():
                revealed.append(decoded)
                found = True
    if not found:
        return text, False
    return text + "\n" + "\n".join(revealed), True


def normalize(text: str) -> NormalizeResult:
    findings: list[str] = []
    current = text

    nfkc = unicodedata.normalize("NFKC", current)
    if nfkc != current:
        findings.append("normalize/nfkc")
        current = nfkc

    current, hit = _strip_tag_block(current)
    if hit:
        findings.append("normalize/unicode-tag-block")

    current, hit = _strip_invisibles(current)
    if hit:
        findings.append("normalize/zero-width-or-bidi")

    current, hit = _fold_confusables(current)
    if hit:
        findings.append("normalize/confusable-folding")

    decoded_any = False
    for _ in range(_MAX_PASSES):
        current, hit = _decode_embedded_blobs(current)
        if not hit:
            break
        decoded_any = True
    if decoded_any:
        findings.append("normalize/embedded-encoding")

    return NormalizeResult(text=current, findings=findings)
