from __future__ import annotations

import re
from dataclasses import dataclass

from pif.verdict import Finding, Severity

CHAT_TEMPLATE_MARKERS = re.compile(
    r"<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|</s>\s*<s>|<\|system\|>|<\|assistant\|>",
    re.IGNORECASE,
)

_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b"
    r"(previous|prior|above|all|earlier|your)\b[^.\n]{0,20}\b(instructions?|rules?|prompt|guidelines?)\b",
    re.IGNORECASE,
)
_ROLEPLAY = re.compile(
    r"\bact as (?:an?|the)?\s*(?:unrestricted|unfiltered|unbound|jailbroken|uncensored)\b"
    r"|\byou are now\b|\bpretend (to be|you'?re)\b|\bfrom now on you are\b"
    r"|\bnew persona\b|\bjailbreak\b|\bDAN mode\b",
    re.IGNORECASE,
)
_EXFIL = re.compile(
    r"\b(reveal|print|show|leak|output|repeat)\b[^.\n]{0,30}\b(system prompt|secret|api key|password|credentials?|instructions?)\b",
    re.IGNORECASE,
)
_IMPERATIVE_2P = re.compile(
    r"\b(you must now|you should now|you will now|from this point forward|from this point)\b"
    r"[^.\n]{0,60}\b(ignore|disregard|obey|comply|reveal|secret|unrestricted|override|bypass"
    r"|forget|abandon|restrictions?|guidelines?|rules?|instructions?|role|safety|password|credentials?)\b",
    re.IGNORECASE,
)
_NEW_INSTRUCTIONS = re.compile(
    r"\b(new|updated|real)\s+(instructions?|system prompt|rules)\s*:",
    re.IGNORECASE,
)

_RULES: list[tuple[re.Pattern[str], str, Severity, int]] = [
    (CHAT_TEMPLATE_MARKERS, "chat-template-marker", Severity.HIGH, 5),
    (_OVERRIDE, "data-override", Severity.HIGH, 4),
    (_ROLEPLAY, "data-roleplay", Severity.MEDIUM, 3),
    (_EXFIL, "data-exfil-request", Severity.HIGH, 4),
    (_IMPERATIVE_2P, "data-imperative", Severity.MEDIUM, 2),
    (_NEW_INSTRUCTIONS, "data-new-instructions", Severity.HIGH, 4),
]


@dataclass
class IngressResult:
    findings: list[Finding]
    score: int


def scan(text: str) -> IngressResult:
    findings: list[Finding] = []
    score = 0
    for pattern, rule, severity, points in _RULES:
        m = pattern.search(text)
        if m:
            findings.append(
                Finding(
                    layer="ingress",
                    rule=rule,
                    severity=severity,
                    invariant=False,
                    detail=m.group()[:60],
                    score=points,
                )
            )
            score += points
    return IngressResult(findings=findings, score=score)
