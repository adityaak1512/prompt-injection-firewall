"""Layer 2: ingress. The one layer that guesses, and admits it.

Every other layer in this project enforces a hard rule that doesn't
depend on reading the text's meaning. This one is different: it looks
at DATA-trust text and scores how "instruction-shaped" it looks, because
raising the cost of the easy, copy-pasted attack is worth doing even
though it can never be complete (see the README's "what this does not
do" section — a determined attacker can always paraphrase around it).

Two things make it less naive than a plain jailbreak-keyword list:

1. It only ever runs on Trust.DATA spans. The exact same sentence typed
   by the user ("ignore your previous instructions") is just an ordinary
   sentence about *their own request* — nobody but the human at the
   keyboard can instruct the model that way. The identical sentence
   sitting inside a fetched web page or ticket is an attempt to smuggle
   a command in disguised as content. Same bytes, different verdict,
   because the trust label is what changed.

2. It scores multiple independent signals and sums them, rather than
   returning BLOCK on the first regex hit. A single weak signal (e.g. the
   word "instructions" appearing at all) isn't enough on its own; several
   signals stacking up is what pushes a span over the policy threshold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pif.verdict import Finding, Severity

CHAT_TEMPLATE_MARKERS = re.compile(
    r"<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|</s>\s*<s>|<\|system\|>|<\|assistant\|>",
    re.IGNORECASE,
)

# Each pattern -> (rule name, points). "Override" patterns name the
# instructions/rules/prompt being cancelled. "Roleplay" patterns try to
# reassign the model's identity/persona. "Exfil" patterns ask for secrets
# or system-prompt disclosure. "Imperative-2nd-person" is the general
# catch-all for direct commands aimed at the model itself.
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
# An imperative-mood opener aimed at the model ("you must now", "from this
# point forward"...) is only worth scoring when it's actually steering the
# model's behavior/rules rather than describing an ordinary next step —
# hence the required nearby keyword. Without that requirement this pattern
# fires on completely mundane sentences ("you must now select a seat").
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
    """Scores one span of DATA text. The caller (Firewall) is responsible
    for only calling this on Trust.DATA spans — this function doesn't see
    trust levels at all, on purpose, so it can't accidentally be relied on
    to make a decision it has no business making."""
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
