"""The knobs a developer turns when wiring this firewall into an app.

Deliberately a plain dataclass with plain defaults — no config file
format, no environment-variable magic. If you want different behavior,
you construct a different Policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    # ingress is the only scored layer. A DATA span whose summed score
    # crosses block_threshold is BLOCK; crossing flag_threshold but not
    # block_threshold is FLAG (allowed, but worth logging/reviewing).
    block_threshold: int = 5
    flag_threshold: int = 2

    # Secrets that must never appear in model output, in any encoding.
    canaries: tuple[str, ...] = field(default_factory=tuple)

    # Hosts (and their subdomains) that URLs/markdown-images in output
    # are allowed to point at. Anything else in a reply is blocked.
    url_allowlist: tuple[str, ...] = field(default_factory=tuple)

    # Tool "effect" tags (e.g. "SPEND", "EXFIL", "DELETE") that are refused
    # outright regardless of a tool's own guard.
    forbidden_effects: frozenset[str] = frozenset()

    # Layers can be switched off individually, e.g. to reproduce a
    # "no firewall" baseline for a benchmark or a training exercise.
    # Layer names: normalize, ingress, provenance, toolauth, egress
    enabled_layers: frozenset[str] = frozenset(
        {"normalize", "ingress", "provenance", "toolauth", "egress"}
    )

    def layer_on(self, name: str) -> bool:
        return name in self.enabled_layers
