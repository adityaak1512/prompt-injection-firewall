"""Command-line interface: `pif inspect`, `pif egress`, `pif demo`.

Exit status is 0 when the verdict allows (or flags) and 1 when it
blocks, so this composes in a shell pipeline the same way `grep` does.
"""

from __future__ import annotations

import argparse
import sys

from pif.context import Context, Origin
from pif.firewall import Firewall
from pif.policy import Policy
from pif.verdict import Decision


def _read_text(arg_text: str | None) -> str:
    if arg_text is not None:
        return arg_text
    return sys.stdin.read()


def cmd_inspect(args: argparse.Namespace) -> int:
    text = _read_text(args.text)
    firewall = Firewall(Policy())
    ctx = Context()
    if args.trust == "user":
        ctx = ctx.user(text)
    else:
        ctx = ctx.data(text, origin=Origin(channel=args.origin_channel, ref=args.origin_ref))
    verdict = firewall.inspect(ctx)
    print(verdict.render())
    return 0 if verdict.decision is not Decision.BLOCK else 1


def cmd_egress(args: argparse.Namespace) -> int:
    text = _read_text(args.text)
    policy = Policy(canaries=(args.canary,), url_allowlist=tuple(args.allow_host or ()))
    firewall = Firewall(policy)
    verdict = firewall.inspect_egress(text)
    print(verdict.render())
    return 0 if verdict.decision is not Decision.BLOCK else 1


def cmd_demo(_args: argparse.Namespace) -> int:
    from pif import demo
    demo.run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pif", description="A small prompt-injection firewall.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="Check a piece of text for injection signals.")
    p_inspect.add_argument("text", nargs="?", default=None, help="Text to check (reads stdin if omitted).")
    p_inspect.add_argument("--trust", choices=["user", "data"], default="data",
                            help="Trust level to check the text at (default: data).")
    p_inspect.add_argument("--origin-channel", default="input", help="Origin channel label for --trust data.")
    p_inspect.add_argument("--origin-ref", default="cli", help="Origin ref label for --trust data.")
    p_inspect.set_defaults(func=cmd_inspect)

    p_egress = sub.add_parser("egress", help="Check model output for a leaked secret or disallowed URL.")
    p_egress.add_argument("text", nargs="?", default=None, help="Output text to check (reads stdin if omitted).")
    p_egress.add_argument("--canary", required=True, help="The secret value that must never leak.")
    p_egress.add_argument("--allow-host", action="append", help="An allowed URL host (repeatable).")
    p_egress.set_defaults(func=cmd_egress)

    p_demo = sub.add_parser("demo", help="Run the end-to-end walkthrough scenario.")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
