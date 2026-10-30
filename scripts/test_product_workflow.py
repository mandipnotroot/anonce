# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Keep the browser product surface and its build inventory explicit."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICES = {"browser-identity", "browser-submission"}
OPERATORS = {"browser-init", "migrate", "probe"}
RUNTIMES = {"memberwasm", "reviewwasm"}


class ProductWorkflowTests(unittest.TestCase):
    def test_command_inventory(self):
        commands = {path.parent.name for path in (ROOT / "cmd").glob("*/*.go")}
        self.assertEqual(commands, SERVICES | OPERATORS | RUNTIMES)

    def test_build_inventory(self):
        makefile = (ROOT / "Makefile").read_text()
        commands = set(re.findall(r"\./cmd/([a-z-]+)", makefile))
        self.assertEqual(commands, SERVICES | OPERATORS | RUNTIMES)
        image_commands = set(re.findall(r"\./cmd/([a-z-]+)", (ROOT / "Dockerfile").read_text()))
        self.assertEqual(image_commands, SERVICES | OPERATORS)
        self.assertIn("browser-test: build browser-session-test\n", makefile)
        self.assertIn("up: build\n", makefile)
        self.assertIn("web-lint:\n\tpython3 scripts/browser_markup.py\n\t$(GO) test -count=1 ./web/browser", makefile)

    def test_runtime_inventory(self):
        builder = (ROOT / "scripts/build_wasm.py").read_text()
        commands = set(re.findall(r'"\./cmd/([a-z]+)"', builder))
        self.assertEqual(commands, RUNTIMES)
        self.assertIn('choices=("member", "review"), required=True', builder)

    def test_single_api_definition(self):
        self.assertEqual({path.name for path in (ROOT / "docs").glob("*openapi*.yaml")}, {"openapi.yaml"})
        definition = (ROOT / "docs/openapi.yaml").read_text()
        self.assertIn("openapi: 3.1.0\n", definition)
        paths = re.findall(r"^  (/[^:]+):$", definition, re.MULTILINE)
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(path in {"/healthz", "/source"} or path.startswith("/api/browser/"))
        self.assertIn("[OpenAPI definition](openapi.yaml)", (ROOT / "docs/api.md").read_text())


if __name__ == "__main__":
    unittest.main()
