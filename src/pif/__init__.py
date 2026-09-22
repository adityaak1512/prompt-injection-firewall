"""pif: a small prompt-injection firewall for LLM applications.

The core idea: don't try to read the attacker's mind by pattern-matching
text. Instead, track *where text came from* (trust level) and enforce
hard rules around the model: untrusted text can't become instructions,
the model can't take actions the firewall didn't authorize, and secrets
can't leave in any disguised form.
"""

from pif.verdict import Decision, Finding, Verdict
from pif.context import Context, Origin, Trust
from pif.policy import Policy
from pif.firewall import Firewall

__all__ = [
    "Decision",
    "Finding",
    "Verdict",
    "Context",
    "Origin",
    "Trust",
    "Policy",
    "Firewall",
]

__version__ = "0.1.0"
