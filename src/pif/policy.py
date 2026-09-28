"""The knobs a developer turns when wiring this firewall into an app.

Deliberately a plain dataclass with plain defaults — no config file
format, no environment-variable magic. If you want different behavior,
you construct a different Policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    block_threshold: int = 5
    flag_threshold: int = 2

    canaries: tuple[str, ...] = field(default_factory=tuple)

    url_allowlist: tuple[str, ...] = field(default_factory=tuple)

    forbidden_effects: frozenset[str] = frozenset()

    enabled_layers: frozenset[str] = frozenset(
        {"normalize", "ingress", "provenance", "toolauth", "egress"}
    )

    def layer_on(self, name: str) -> bool:
        return name in self.enabled_layers
