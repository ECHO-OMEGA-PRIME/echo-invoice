from __future__ import annotations

import ast
import os
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from credential_config import required_env


_SECRET_NAME = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)


class RequiredEnvironmentTests(unittest.TestCase):
    def test_missing_and_blank_values_fail_closed(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "REQUIRED_TEST_SECRET"):
                required_env("REQUIRED_TEST_SECRET")
        with patch.dict(os.environ, {"REQUIRED_TEST_SECRET": "   "}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "REQUIRED_TEST_SECRET"):
                required_env("REQUIRED_TEST_SECRET")

    def test_configured_value_is_returned_unchanged(self) -> None:
        with patch.dict(os.environ, {"REQUIRED_TEST_SECRET": "fixture-value"}, clear=True):
            self.assertEqual(required_env("REQUIRED_TEST_SECRET"), "fixture-value")

    def test_runtime_has_no_nonempty_secret_env_default(self) -> None:
        findings: list[str] = []
        root = Path(__file__).resolve().parents[1]
        for source in sorted(root.glob("*.py")):
            if source.name.startswith("test"):
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr not in {"get", "getenv"} or len(node.args) < 2:
                    continue
                name, default = node.args[0], node.args[1]
                if (
                    isinstance(name, ast.Constant)
                    and isinstance(name.value, str)
                    and _SECRET_NAME.search(name.value)
                    and isinstance(default, ast.Constant)
                    and isinstance(default.value, str)
                    and default.value
                ):
                    findings.append(f"{source.name}:{node.lineno}:{name.value}")
        self.assertEqual(findings, [], "non-empty credential defaults remain")


if __name__ == "__main__":
    unittest.main()
