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
