"""Command-line interface for the password policy breach analyzer."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze, iter_passwords
from .policy import Policy
from .report import to_html, to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ppa",
        description=(
            "Analyze a password policy against a real breach corpus "
            "(e.g. rockyou.txt) and estimate brute-force resistance."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument(
        "-w", "--wordlist", required=True,
        help="Path to the breach corpus / wordlist (one password per line).",
    )
    parser.add_argument(
        "--policy", help="Path to a JSON policy file. CLI flags override its fields.",
    )

    # Policy knobs (override the JSON file if both are given).
    g = parser.add_argument_group("policy options")
    g.add_argument("--min-length", type=int, help="Minimum length (default 8).")
    g.add_argument("--max-length", type=int, help="Maximum length (optional).")
    g.add_argument("--require-lower", action="store_true", help="Require a lowercase letter.")
    g.add_argument("--require-upper", action="store_true", help="Require an uppercase letter.")
    g.add_argument("--require-digit", action="store_true", help="Require a digit.")
    g.add_argument("--require-symbol", action="store_true", help="Require a symbol.")
    g.add_argument("--min-char-classes", type=int, help="Require at least N character classes.")

    # Output control.
    o = parser.add_argument_group("output options")
    o.add_argument(
        "-f", "--format", choices=["text", "json", "html"], default="text",
        help="Report format (default: text).",
    )
    o.add_argument("-o", "--output", help="Write the report to a file instead of stdout.")
    o.add_argument(
        "--limit", type=int,
        help="Only examine the first N passwords (useful on slow machines).",
    )
    return parser


def resolve_policy(args: argparse.Namespace) -> Policy:
    """Build a Policy from an optional JSON file plus CLI overrides."""
    policy = Policy.from_json_file(args.policy) if args.policy else Policy()
    overrides = {
        "min_length": args.min_length,
        "max_length": args.max_length,
        "min_char_classes": args.min_char_classes,
    }
    for field_name, value in overrides.items():
        if value is not None:
            setattr(policy, field_name, value)
    # Boolean flags only turn things ON (store_true); they never turn off a
    # requirement that came from the JSON file.
    for flag in ("require_lower", "require_upper", "require_digit", "require_symbol"):
        if getattr(args, flag):
            setattr(policy, flag, True)
    return policy


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    policy = resolve_policy(args)

    try:
        passwords = iter_passwords(args.wordlist)
        result = analyze(policy, passwords, limit=args.limit)
    except FileNotFoundError:
        print(f"error: wordlist not found: {args.wordlist}", file=sys.stderr)
        return 2

    if result.total == 0:
        print("error: wordlist was empty.", file=sys.stderr)
        return 1

    renderers = {"text": to_text, "json": to_json, "html": to_html}
    report = renderers[args.format](result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
