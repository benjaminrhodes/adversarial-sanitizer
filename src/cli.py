"""CLI interface for adversarial sanitizer."""

import sys
import argparse
from typing import List

from src.sanitizer import Sanitizer


def detect_cmd(inputs: List[str]) -> int:
    """Run detect command.

    Args:
        inputs: List of input strings to check.

    Returns:
        1 if any input is adversarial, 0 otherwise.
    """
    sanitizer = Sanitizer()
    has_adversarial = False
    for inp in inputs:
        result = sanitizer.detect(inp)
        if result.is_adversarial:
            print(f"ADVERSARIAL: {inp}")
            print(f"  Patterns: {result.detected_patterns}")
            has_adversarial = True
        else:
            print(f"SAFE: {inp}")
    return 1 if has_adversarial else 0


def sanitize_cmd(inputs: List[str]) -> int:
    """Run sanitize command.

    Args:
        inputs: List of input strings to sanitize.

    Returns:
        0 on success.
    """
    sanitizer = Sanitizer()
    for inp in inputs:
        result = sanitizer.sanitize(inp)
        if result.was_sanitized:
            print(f"SANITIZED: {result.sanitized}")
        else:
            print(f"ORIGINAL: {result.sanitized}")
    return 0


def main(args: List[str] = None) -> int:
    """Main CLI entry point.

    Args:
        args: Command line arguments. Defaults to sys.argv.

    Returns:
        Exit code.
    """
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Adversarial input sanitizer for ML models")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    detect_parser = subparsers.add_parser("detect", help="Detect adversarial patterns")
    detect_parser.add_argument("inputs", nargs="+", help="Inputs to check")

    sanitize_parser = subparsers.add_parser("sanitize", help="Sanitize adversarial inputs")
    sanitize_parser.add_argument("inputs", nargs="+", help="Inputs to sanitize")

    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 1

    if parsed.command == "detect":
        return detect_cmd(parsed.inputs)
    elif parsed.command == "sanitize":
        return sanitize_cmd(parsed.inputs)

    return 0


if __name__ == "__main__":
    sys.exit(main())
