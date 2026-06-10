"""Extract the release notes for a given version from CHANGELOG.md.

Prints the section for the requested version from CHANGELOG.md to stdout (or an
output file). Exits with a non-zero status if the section is not found.

Usage: python scripts/extract_changelog.py <version> [output-file]

The version may also be supplied via the GITHUB_REF_NAME environment variable (the
git tag that triggered the release workflow), in which case the positional version
argument may be omitted. If an output file path is given the notes are written
there; otherwise they are printed to stdout.
"""

import os
import re
import sys
from pathlib import Path


def main() -> None:
    args = sys.argv[1:]

    if args:
        version = args[0]
        output_file = args[1] if len(args) > 1 else None
    else:
        version = os.environ.get("GITHUB_REF_NAME", "")
        output_file = None

    if not version:
        print("No version given (argument or GITHUB_REF_NAME)", file=sys.stderr)
        sys.exit(1)

    root = Path(__file__).parent.parent
    text = (root / "CHANGELOG.md").read_text()

    pattern = r"(?sm)^## \[" + re.escape(version) + r"\][^\n]*\n(.*?)(?=^## \[|\Z)"
    match = re.search(pattern, text)
    if not match:
        print(f"No release notes found for {version}", file=sys.stderr)
        sys.exit(1)

    notes = match.group(1).strip() + "\n"

    if output_file:
        Path(output_file).write_text(notes)
    else:
        sys.stdout.write(notes)


if __name__ == "__main__":
    main()
