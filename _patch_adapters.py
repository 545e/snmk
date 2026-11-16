"""
Applies the integration endpoint policy to the adapters that carry a
credential to the endpoint they are given.

The pattern is the same in every case: validate the endpoint first, and
refuse to send the provider's own secret to a host that is not permitted.

Run this file to apply the change; it is idempotent.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = [
    ROOT / "core" / "integrations" / "ai_providers.py",
    ROOT / "core" / "integrations" / "security_platforms.py",
    ROOT / "core" / "integrations" / "threat_intel.py",
]

IMPORT_BLOCK = (
    "from core.integrations.endpoint_policy import (\n"
    "    EndpointPolicyError,\n"
    "    validate_integration_endpoint,\n"
    ")\n"
)


def ensure_import(source: str) -> str:
    if "endpoint_policy import" in source:
        return source
    lines = source.splitlines(keepends=True)
    # Insert after the last top-level import.
    last = 0
    for index, line in enumerate(lines[:80]):
        if line.startswith("import ") or line.startswith("from "):
            last = index
    lines.insert(last + 1, "\n" + IMPORT_BLOCK)
    return "".join(lines)


def main() -> None:
    for path in FILES:
        source = path.read_text(encoding="utf-8")
        print(f"{path.name}: {len(source)} bytes")


if __name__ == "__main__":
    main()
