"""Suggest the next release version from the pending towncrier news fragments.

Maps the highest-impact fragment type in `release-notes/` onto a SemVer bump of
the most recent git tag, honouring the pre-1.0 convention (breaking changes and
features bump the minor while the major is 0). Prints the recommendation and makes
no changes. The suggestion is advisory — confirm it before passing it to
`just release`.

Usage: python scripts/suggest_version.py
"""

import re
import subprocess
import sys
from pathlib import Path

# Bump levels, highest impact first.
MAJOR, MINOR, PATCH = 3, 2, 1

# Fragment type -> bump level.
LEVELS = {
    "breaking": MAJOR,
    "removed": MAJOR,
    "added": MINOR,
    "changed": MINOR,
    "deprecated": MINOR,
    "fixed": PATCH,
    "security": PATCH,
}
LEVEL_NAME = {MAJOR: "major", MINOR: "minor", PATCH: "patch"}


def latest_tag() -> str:
    """Return the most recent reachable git tag, or "" if there is none."""
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    return result.stdout.strip()


def parse_version(tag: str) -> tuple[int, int, int]:
    """Extract a (major, minor, patch) triple from a tag like `1.2.3` or `1.2.3rc1`."""
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", tag)
    if not match:
        return (0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def pending_types(fragment_dir: Path) -> set[str]:
    """Return the set of known fragment types present in the news-fragment directory."""
    found: set[str] = set()
    for path in sorted(fragment_dir.iterdir()):
        if not path.is_file():
            continue
        frag_type = next((part for part in path.name.split(".") if part in LEVELS), None)
        if frag_type:
            found.add(frag_type)
    return found


def bump(current: tuple[int, int, int], level: int) -> str:
    """Apply a bump level to a version triple, respecting the pre-1.0 convention."""
    major, minor, patch = current
    if major == 0:
        # Pre-1.0: breaking changes and features bump the minor; fixes bump the patch.
        return f"0.{minor + 1}.0" if level >= MINOR else f"0.{minor}.{patch + 1}"
    if level == MAJOR:
        return f"{major + 1}.0.0"
    if level == MINOR:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def main() -> None:
    fragment_dir = Path(__file__).parent.parent / "release-notes"
    found = pending_types(fragment_dir)

    if not found:
        print("No pending news fragments in release-notes/ — nothing to release.")
        sys.exit(1)

    level = max(LEVELS[frag_type] for frag_type in found)
    tag = latest_tag()
    current = parse_version(tag)
    suggestion = bump(current, level)

    driver = ", ".join(sorted(frag_type for frag_type in found if LEVELS[frag_type] == level))
    base = tag or "0.0.0 (no tags found)"
    note = "  [pre-1.0: breaking & features bump the minor]" if current[0] == 0 else ""
    print(f"{base} -> {suggestion}  ({LEVEL_NAME[level]}: {driver}){note}")


if __name__ == "__main__":
    main()
