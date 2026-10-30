"""Small offline prose checks; no application install or live link requests."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from classify_changes import PROSE_FILES


def check_document(root: Path, name: str) -> list[str]:
    path = root / name
    if path.is_symlink():
        return [f"{name}: not a regular prose file"]
    if not path.exists():  # An eligible prose-only deletion is permitted.
        return []
    if not path.is_file():
        return [f"{name}: not a regular prose file"]
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeError:
        return [f"{name}: not UTF-8"]
    errors = []
    if not text.strip() or not text.endswith("\n"):
        errors.append(f"{name}: must be nonempty and end with a newline")
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        if line.rstrip() != line:
            errors.append(f"{name}:{number}: trailing whitespace")
        if re.match(r"^(<<<<<<<|=======|>>>>>>>)(?: |$)", line):
            errors.append(f"{name}:{number}: unresolved conflict marker")
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})(.*)$", line)
        if marker:
            run, tail = marker.groups()
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not tail.strip():
                fence = None
            continue
        if fence:
            continue
        # Inline local Markdown links/images, including code-formatted labels.
        # Remote links and fragment anchors are not fetched/validated offline.
        for target in re.findall(r"\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)", line):
            link = urlsplit(target.strip("<>"))
            if link.scheme or link.netloc or not link.path:
                continue
            destination = (path.parent / unquote(link.path)).resolve()
            if not destination.is_relative_to(root.resolve()) or not destination.exists():
                errors.append(f"{name}:{number}: missing/unsafe local link {target}")
    if fence:
        errors.append(f"{name}: unclosed fenced code block")
    return errors


def main() -> int:
    errors = [error for name in sorted(PROSE_FILES) for error in check_document(Path.cwd(), name)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Audited prose: UTF-8, whitespace, conflict markers, fences and local links passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
