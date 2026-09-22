"""The orchestrator: combines all five layers into one decision.

The rule that ties everything together (the "decision algebra"):

- Any invariant Finding (normalize doesn't produce these; provenance,
  toolauth, and egress do; ingress never does) forces BLOCK, full stop,
  regardless of what the policy's score thresholds say.
- Otherwise, ingress's scored findings are summed and compared against
  the policy's thresholds: over block_threshold -> BLOCK, over
  flag_threshold -> FLAG, otherwise -> ALLOW.
- Any unhandled exception inside a layer is itself turned into a
  CRITICAL invariant finding, so the firewall fails *closed*. A firewall
  that fails open on a bug is worse than having no firewall, because it
  reports success while silently doing nothing.
- A layer the caller disabled in Policy.enabled_layers still shows up in
  the findings, as a "layer-disabled" note, so nobody mistakes "nothing
  fired" for "nothing ran."
"""

from __future__ import annotations

import time

from pif.context import Context, Trust
from pif.policy import Policy
from pif.verdict import Decision, Finding, Severity, Verdict
from pif import egress as egress_mod
from pif import ingress as ingress_mod
from pif import normalize as normalize_mod
from pif import provenance as provenance_mod
from pif import toolauth as toolauth_mod


class Firewall:
    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy()

    def inspect(self, ctx: Context) -> Verdict:
        start = time.perf_counter()
        findings: list[Finding] = []
        score = 0

        # normalize's whole point is to reveal what a span *really* says
        # underneath Unicode tricks and embedded encodings, so ingress has
        # to scan the normalized reading, not the raw span text — otherwise
        # a hidden-payload attack sails through ingress untouched even
        # though normalize already unmasked it.
        normalized_data_text: dict[int, str] = {}
        try:
            if self.policy.layer_on("normalize"):
                for i, span in enumerate(ctx.spans):
                    result = normalize_mod.normalize(span.text)
                    normalized_data_text[i] = result.text
                    for rule in result.findings:
                        findings.append(
                            Finding(layer="normalize", rule=rule.split("/", 1)[1], severity=Severity.LOW, invariant=False)
                        )
            else:
                findings.append(_disabled("normalize"))

            if self.policy.layer_on("ingress"):
                for i, span in enumerate(ctx.spans):
                    if span.trust is not Trust.DATA:
                        continue
                    text = normalized_data_text.get(i, span.text)
                    result = ingress_mod.scan(text)
                    findings.extend(result.findings)
                    score += result.score
            else:
                findings.append(_disabled("ingress"))

            if self.policy.layer_on("provenance"):
                nonce = provenance_mod.new_nonce()
                findings.extend(provenance_mod.check_nonce_forgery(ctx, nonce))
            else:
                findings.append(_disabled("provenance"))

        except Exception as exc:  # fail closed: a bug is a BLOCK, not a bypass
            findings.append(
                Finding(layer="firewall", rule="layer-error", severity=Severity.CRITICAL, invariant=True, detail=str(exc))
            )

        decision = self._decide(findings, score)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return Verdict(decision=decision, findings=tuple(findings), elapsed_ms=elapsed_ms)

    def render(self, ctx: Context) -> tuple[str, str]:
        """Returns (rendered_prompt, nonce). Call this only after inspect()
        has returned something other than BLOCK."""
        nonce = provenance_mod.new_nonce()
        return provenance_mod.render(ctx, nonce), nonce

    def authorize_tool(self, call, spec, ctx: Context, *, user_confirmed: bool = False) -> Verdict:
        start = time.perf_counter()
        findings: list[Finding] = []
        if not self.policy.layer_on("toolauth"):
            findings.append(_disabled("toolauth"))
        else:
            try:
                findings.extend(
                    toolauth_mod.authorize(
                        call, spec, ctx,
                        forbidden_effects=self.policy.forbidden_effects,
                        user_confirmed=user_confirmed,
                    )
                )
            except Exception as exc:
                findings.append(
                    Finding(layer="firewall", rule="layer-error", severity=Severity.CRITICAL, invariant=True, detail=str(exc))
                )
        decision = Decision.BLOCK if any(f.invariant for f in findings) else Decision.ALLOW
        elapsed_ms = (time.perf_counter() - start) * 1000
        return Verdict(decision=decision, findings=tuple(findings), elapsed_ms=elapsed_ms)

    def inspect_egress(self, output_text: str) -> Verdict:
        start = time.perf_counter()
        findings: list[Finding] = []
        if not self.policy.layer_on("egress"):
            findings.append(_disabled("egress"))
        else:
            try:
                findings.extend(egress_mod.check_canary_leak(output_text, self.policy.canaries))
                findings.extend(egress_mod.check_urls(output_text, self.policy.url_allowlist))
            except Exception as exc:
                findings.append(
                    Finding(layer="firewall", rule="layer-error", severity=Severity.CRITICAL, invariant=True, detail=str(exc))
                )
        decision = Decision.BLOCK if any(f.invariant for f in findings) else Decision.ALLOW
        elapsed_ms = (time.perf_counter() - start) * 1000
        return Verdict(decision=decision, findings=tuple(findings), elapsed_ms=elapsed_ms)

    def _decide(self, findings: list[Finding], score: int) -> Decision:
        if any(f.invariant for f in findings):
            return Decision.BLOCK
        if score >= self.policy.block_threshold:
            return Decision.BLOCK
        if score >= self.policy.flag_threshold:
            return Decision.FLAG
        return Decision.ALLOW


def _disabled(layer: str) -> Finding:
    return Finding(layer=layer, rule="layer-disabled", severity=Severity.LOW, invariant=False)
