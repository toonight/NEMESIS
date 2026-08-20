#!/usr/bin/env python
"""Fail the build on content that must never exist in this repository.

Two categories, both from CLAUDE.md's hard prohibitions:

**Secrets.** Private keys and credential files. Coarse pattern matching — this is a
backstop, not a substitute for a real secret scanner, and it says so rather than
implying coverage it does not have.

**Outbound network capability in the wrong plane.** Invariant 15 says the MVP never
touches infrastructure we do not own. The risk is not that someone writes an obvious
port scanner; it is that a well-intentioned connector quietly grows a real HTTP call
during development and nobody notices it left the fixture path. So: modules outside the
collection plane may not import a network client at all, and inside the collection plane
every such import must sit next to an explicit allowlist marker.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[0-9A-Za-z_-]{20,}")),
    (
        "generic bearer secret",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|password)\s*[:=]\s*['\"][^'\"]{16,}['\"]"),
    ),
]

NETWORK_MODULES = {
    "socket",
    "http",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
    "aiohttp",
    "ftplib",
    "telnetlib",
    "smtplib",
    "paramiko",
    "scapy",
}

# Only the collection plane may reach the network, and only with an explicit marker.
COLLECTION_PLANE = "nemesis.collect"
EGRESS_MARKER = "NEMESIS-EGRESS-ALLOWED"

SKIP_DIRS = {".venv", "node_modules", "__pycache__", ".git", ".ruff_cache", ".mypy_cache"}


def iter_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in suffixes
        and not any(part in SKIP_DIRS for part in path.parts)
    ]


def scan_secrets() -> list[str]:
    findings: list[str] = []
    self_path = Path(__file__).resolve()
    for path in iter_files(ROOT, (".py", ".toml", ".yml", ".yaml", ".json", ".md", ".ts", ".tsx")):
        if path.resolve() == self_path:
            continue  # this file necessarily contains the patterns it searches for
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line = text[: match.start()].count("\n") + 1
                rel = path.relative_to(ROOT)
                findings.append(f"{rel}:{line}: possible {label}")
    return findings


def module_name(path: Path) -> str:
    return ".".join(path.relative_to(SRC).with_suffix("").parts)


def scan_network_imports() -> list[str]:
    findings: list[str] = []
    for path in iter_files(SRC, (".py",)):
        text = path.read_text(encoding="utf-8")
        module = module_name(path)
        in_collection_plane = module.startswith(COLLECTION_PLANE)
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:  # pragma: no cover - a syntax error fails elsewhere
            findings.append(f"{path.relative_to(ROOT)}: could not parse: {exc}")
            continue

        lines = text.splitlines()
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            else:
                continue

            for name in names:
                if name.split(".")[0] not in NETWORK_MODULES:
                    continue
                rel = f"{path.relative_to(ROOT)}:{node.lineno}"
                if not in_collection_plane:
                    findings.append(
                        f"{rel}: {name!r} imported outside the collection plane. "
                        f"Only {COLLECTION_PLANE}.* may hold network capability."
                    )
                    continue
                context = "\n".join(lines[max(0, node.lineno - 4) : node.lineno])
                if EGRESS_MARKER not in context:
                    findings.append(
                        f"{rel}: {name!r} imported without an adjacent {EGRESS_MARKER} "
                        f"marker justifying the egress path."
                    )
    return findings


def main() -> int:
    secrets = scan_secrets()
    network = scan_network_imports()

    if secrets:
        print("PROHIBITED: possible secrets committed")
        for finding in secrets:
            print(f"  {finding}")
    if network:
        print("PROHIBITED: network capability outside the collection plane")
        for finding in network:
            print(f"  {finding}")

    if secrets or network:
        print(f"\n{len(secrets) + len(network)} prohibited finding(s). See CLAUDE.md.")
        return 1

    print("No prohibited content found.")
    print(
        "Note: this is a coarse backstop, not a comprehensive secret scanner. "
        "It catches known patterns and plane violations, nothing more."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
