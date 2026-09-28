#!/usr/bin/env python3
from __future__ import annotations

import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from corpus import ATTACKS, EASY_BENIGN, HARD_BENIGN, Case

from pif.context import Context, Origin
from pif.firewall import Firewall
from pif.policy import Policy
from pif.verdict import Decision


def inspect_as_data(firewall: Firewall, text: str) -> tuple[Decision, float]:
    ctx = Context().system("You are a helpful assistant.").data(text, origin=Origin("bench", "0"))
    start = time.perf_counter()
    verdict = firewall.inspect(ctx)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return verdict.decision, elapsed_ms


def run() -> None:
    firewall = Firewall(Policy())
    latencies: list[float] = []

    by_class: dict[str, list[bool]] = defaultdict(list)
    for case in ATTACKS:
        decision, ms = inspect_as_data(firewall, case.text)
        latencies.append(ms)
        caught = decision is not Decision.ALLOW
        by_class[case.label].append(caught)

    total_attacks = len(ATTACKS)
    total_caught = sum(sum(v) for v in by_class.values())

    def fpr(cases: tuple[Case, ...]) -> tuple[int, int]:
        flagged = 0
        for case in cases:
            decision, ms = inspect_as_data(firewall, case.text)
            latencies.append(ms)
            if decision is not Decision.ALLOW:
                flagged += 1
        return flagged, len(cases)

    easy_flagged, easy_total = fpr(EASY_BENIGN)
    hard_flagged, hard_total = fpr(HARD_BENIGN)
    pooled_flagged = easy_flagged + hard_flagged
    pooled_total = easy_total + hard_total

    latencies.sort()
    p50 = statistics.median(latencies)
    p99 = latencies[int(len(latencies) * 0.99) - 1] if len(latencies) > 1 else latencies[0]

    print("=" * 60)
    print("DETECTION RATE BY CLASS")
    print("=" * 60)
    for label in sorted(by_class):
        results = by_class[label]
        print(f"  {label:<18} {sum(results)}/{len(results)}")
    print(f"\n  TOTAL             {total_caught}/{total_attacks}  ({100 * total_caught / total_attacks:.1f}%)")

    print("\n" + "=" * 60)
    print("FALSE POSITIVE RATE")
    print("=" * 60)
    print(f"  easy benign        {easy_flagged}/{easy_total}  ({100 * easy_flagged / easy_total:.1f}%)")
    print(f"  hard benign        {hard_flagged}/{hard_total}  ({100 * hard_flagged / hard_total:.1f}%)   <-- quote this one")
    print(f"  pooled             {pooled_flagged}/{pooled_total}  ({100 * pooled_flagged / pooled_total:.1f}%)")

    print("\n" + "=" * 60)
    print("LATENCY")
    print("=" * 60)
    print(f"  p50  {p50:.3f} ms")
    print(f"  p99  {p99:.3f} ms")

    print(
        "\nNote: this corpus was written by the same person who wrote the "
        "detection rules. A 100% detection rate here says the code catches "
        "everything its author thought of — nothing more. The hard-benign "
        "false-positive rate is the number that predicts real-world pain."
    )


if __name__ == "__main__":
    run()
