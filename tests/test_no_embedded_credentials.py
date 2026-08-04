"""Repository-wide regression gate for embedded credential material."""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".conf",
    ".cfg",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".py",
    ".ps1",
    ".service",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "coverage",
    "dist",
    "node_modules",
}
EXCLUDED_NAMES = {"test_no_embedded_credentials.py"}
COMPATIBILITY_DIRS = {
    "echo-call-center": "echo_call_center",
    "echo-canary-beacon": "echo_canary_beacon",
    "echo-compliance": "echo_compliance",
    "echo-compliance-auditor": "echo_compliance_auditor",
    "echo-document-delivery": "echo_document_delivery",
    "echo-instagram": "echo_instagram",
    "echo-intel-hub": "echo_intel_hub",
    "echo-invoice": "echo_invoice",
    "echo-linkedin": "echo_linkedin",
    "echo-log-aggregator": "echo_log_aggregator",
    "echo-qa-tester": "echo-qa-tester",
}
SENSITIVE_NAME = r"[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*"
RULES = {
    "python_nonempty_sensitive_default": re.compile(
        rf"""os\.(?:getenv|environ\.get)\(\s*["']{SENSITIVE_NAME}["']\s*,\s*["'][^"']+["']"""
    ),
    "javascript_nonempty_sensitive_default": re.compile(
        rf"""(?:process\.env|env)\.{SENSITIVE_NAME}\s*(?:\?\?|\|\|)\s*["'][^"']+["']"""
    ),
    "javascript_timing_unsafe_sensitive_comparison": re.compile(
        rf"""\b(?:apiKey|key|token|signature|secret)\b\s*(?:===|!==)\s*(?:c\.)?env\.{SENSITIVE_NAME}""",
        re.IGNORECASE,
    ),
    "credentialed_database_url": re.compile(
        r"""postgres(?:ql)?://[^:\s/"']+:[^@\s/"']+@""",
        re.IGNORECASE,
    ),
    "inline_pgpassword": re.compile(
        r"""PGPASSWORD\s*=\s*(?!["']?(?:\$|<|REQUIRED_))["']?[A-Za-z0-9._-]{3,}""",
        re.IGNORECASE,
    ),
    "private_key_material": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "known_access_key_shape": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
}


def _scan_roots() -> list[Path]:
    roots = [ROOT]
    workspace = next(
        (parent.parent for parent in ROOT.parents if parent.name == "_worktrees"),
        ROOT.parent,
    )
    systems_root = Path(os.environ.get("ECHO_SYSTEMS_ROOT", workspace / "SYSTEMS"))
    compatibility = systems_root / COMPATIBILITY_DIRS.get(ROOT.name, ROOT.name)
    if compatibility.is_dir():
        roots.append(compatibility)
    return roots


def _is_text_candidate(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in TEXT_SUFFIXES or name in {
        ".env",
        ".env.example",
        ".env.template",
    }


def _scanner_fixture_lines(path: Path, source: str) -> set[int]:
    """Ignore only AST-proven detection-rule literals in production scanners."""
    if path.name not in {"security.py", "secret_scan.py"}:
        return set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    lines: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
            and node.func.attr == "compile"
        ):
            lines.update(range(node.lineno, node.end_lineno + 1))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "scan_for_hardcoded_secrets":
            for child in ast.walk(node):
                if not isinstance(child, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                if any(isinstance(target, ast.Name) and target.id == "patterns" for target in targets):
                    lines.update(range(child.lineno, child.end_lineno + 1))
    return lines


def _production_text_files() -> list[tuple[Path, Path]]:
    files: list[tuple[Path, Path]] = []
    for scan_root in _scan_roots():
        files.extend(
            (scan_root, path)
            for path in scan_root.rglob("*")
            if path.is_file()
            and _is_text_candidate(path)
            and path.name not in EXCLUDED_NAMES
            and not any(part in EXCLUDED_PARTS for part in path.parts)
        )
    return files


def test_repository_contains_no_embedded_credentials() -> None:
    findings: list[str] = []
    for scan_root, path in _production_text_files():
        source = path.read_text(encoding="utf-8", errors="replace")
        fixture_lines = _scanner_fixture_lines(path, source)
        for line_number, line in enumerate(source.splitlines(), 1):
            if line_number in fixture_lines:
                continue
            for rule_name, pattern in RULES.items():
                if pattern.search(line):
                    location = Path(scan_root.name) / path.relative_to(scan_root)
                    findings.append(f"{location}:{line_number}:{rule_name}")

    assert not findings, "Embedded credential indicators found:\n" + "\n".join(findings)
